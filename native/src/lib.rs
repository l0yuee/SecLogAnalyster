//! Native work is bounded and detached from Python; only Arrow batches cross
//! the extension boundary. The Python adapter owns source and staging commits.
mod lines;
mod parsers;

use std::fs::File;
use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::ffi::FFI_ArrowArray;
use arrow_array::{Array, ArrayRef, RecordBatch, StructArray, UInt64Array};
use arrow_schema::ffi::FFI_ArrowSchema;
use arrow_schema::{DataType, Field, Schema};
use pyo3::create_exception;
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyCapsule, PyModule};

const COLUMN_COUNT: usize = 26;
const COLUMNS: [&str; COLUMN_COUNT] = [
    "host",
    "log_type",
    "time_created",
    "client_ip",
    "server_ip",
    "server_port",
    "method",
    "uri_stem",
    "uri_query",
    "protocol_version",
    "status",
    "substatus",
    "win32_status",
    "bytes_sent",
    "bytes_received",
    "time_taken_ms",
    "username",
    "user_agent",
    "referer",
    "extra",
    "source_path",
    "source_file",
    "file_sha256",
    "ingest_batch_id",
    "ingested_at",
    "schema_version",
];

create_exception!(_native, UnsupportedInputError, PyValueError);

enum Failure {
    Unsupported(String),
    Parse(String),
    Io(std::io::Error),
}

impl Failure {
    fn into_python(self) -> PyErr {
        match self {
            Self::Unsupported(message) => UnsupportedInputError::new_err(message),
            Self::Parse(message) => PyValueError::new_err(message),
            Self::Io(error) => PyOSError::new_err(error.to_string()),
        }
    }
}

struct Metadata {
    host: String,
    log_type: String,
    source_path: String,
    source_file: String,
    file_sha256: String,
}
struct Row {
    values: [Option<String>; COLUMN_COUNT],
    numeric: [bool; COLUMN_COUNT],
}
enum RowOutcome {
    Record(Row),
    Skipped,
    End,
}

impl Row {
    fn value<'a>(&'a self, index: usize, metadata: &'a Metadata) -> Option<&'a str> {
        match index {
            0 => Some(&metadata.host),
            1 => Some(&metadata.log_type),
            20 => Some(&metadata.source_path),
            21 => Some(&metadata.source_file),
            22 => Some(&metadata.file_sha256),
            _ => self.values[index].as_deref(),
        }
    }

    fn encoded_bytes(&self, metadata: &Metadata) -> usize {
        // Existing parsers emit the first 20 fields; the staging adapter adds
        // three provenance fields. The final three schema columns are absent
        // until conversion and must not count as raw JSON keys here.
        3 + 22
            + (0..23)
                .map(|index| {
                    COLUMNS[index].len()
                        + 3
                        + match self.value(index, metadata) {
                            None => 4,
                            Some(value) if self.numeric[index] => value.len(),
                            Some(value) => json_string_bytes(value),
                        }
                })
                .sum::<usize>()
    }

    fn buffer_bytes(&self, metadata: &Metadata) -> usize {
        // 32-bit string offsets plus a conservative per-row validity byte.
        5 * COLUMN_COUNT
            + (0..COLUMN_COUNT)
                .filter_map(|index| self.value(index, metadata))
                .map(str::len)
                .sum::<usize>()
    }
}

fn json_string_bytes(value: &str) -> usize {
    2 + value
        .bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
            0..=0x1f => 6,
            _ => 1,
        })
        .sum::<usize>()
}

fn capsules<'py>(
    py: Python<'py>,
    array: &dyn Array,
) -> PyResult<(Bound<'py, PyCapsule>, Bound<'py, PyCapsule>)> {
    let schema = FFI_ArrowSchema::try_from(array.data_type())
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let data = FFI_ArrowArray::new(&array.to_data());
    // PyCapsule owns the FFI structs. Their Drop invokes release only if a
    // consumer has not moved ownership and nulled the release callback.
    // Every export creates fresh wrappers retaining the underlying Arc buffers.
    let schema_capsule = PyCapsule::new_with_value(py, schema, c"arrow_schema")?;
    let array_capsule = PyCapsule::new_with_value(py, data, c"arrow_array")?;
    Ok((schema_capsule, array_capsule))
}

#[pyclass(frozen, module = "seclogx_native._native")]
struct NativeArray {
    values: UInt64Array,
}

#[pymethods]
impl NativeArray {
    #[pyo3(signature = (requested_schema=None))]
    fn __arrow_c_array__<'py>(
        &self,
        py: Python<'py>,
        requested_schema: Option<Bound<'py, PyAny>>,
    ) -> PyResult<(Bound<'py, PyCapsule>, Bound<'py, PyCapsule>)> {
        // Consumers may request another physical representation; returning the
        // native representation is permitted by the protocol's best effort rule.
        let _ = requested_schema;
        capsules(py, &self.values)
    }
}

#[pyclass(frozen, module = "seclogx_native._native")]
struct NativeBatch {
    batch: RecordBatch,
    sizes: UInt64Array,
}

#[pymethods]
impl NativeBatch {
    #[pyo3(signature = (requested_schema=None))]
    fn __arrow_c_array__<'py>(
        &self,
        py: Python<'py>,
        requested_schema: Option<Bound<'py, PyAny>>,
    ) -> PyResult<(Bound<'py, PyCapsule>, Bound<'py, PyCapsule>)> {
        let _ = requested_schema;
        capsules(py, &StructArray::from(self.batch.clone()))
    }

    #[getter]
    fn encoded_record_sizes(&self) -> NativeArray {
        NativeArray {
            values: self.sizes.clone(),
        }
    }

    #[getter]
    fn num_rows(&self) -> usize {
        self.batch.num_rows()
    }
}

#[pyclass(module = "seclogx_native._native")]
struct NativeWebReader {
    lines: Option<lines::Lines>,
    metadata: Metadata,
    kind: String,
    fields: Option<parsers::IisLayout>,
    schema: Arc<Schema>,
    pending_row: Option<Row>,
    pending_error: Option<Failure>,
    max_batch_bytes: usize,
    max_batch_rows: usize,
    max_record_bytes: usize,
    max_integer_digits: usize,
    done: bool,
    error_count: u64,
    record_count: u64,
    scanned_lines: u64,
    scanned_bytes: u64,
}

#[pymethods]
impl NativeWebReader {
    #[new]
    #[pyo3(signature = (path, kind, host, log_type, source_path, source_file, file_sha256, schema_columns, *, source_handle=None, max_batch_bytes=16_777_216, max_batch_rows=16_384, max_line_chars=8_388_608, max_record_bytes=33_554_432, max_integer_digits=4300))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: String,
        kind: String,
        host: String,
        log_type: String,
        source_path: String,
        source_file: String,
        file_sha256: String,
        schema_columns: Vec<String>,
        source_handle: Option<isize>,
        max_batch_bytes: usize,
        max_batch_rows: usize,
        max_line_chars: usize,
        max_record_bytes: usize,
        max_integer_digits: usize,
    ) -> PyResult<Self> {
        if kind != "web_access" && kind != "iis" {
            return Err(UnsupportedInputError::new_err(
                "unsupported native parser kind",
            ));
        }
        if schema_columns.iter().map(String::as_str).ne(COLUMNS) {
            return Err(UnsupportedInputError::new_err(
                "native web schema does not match product schema",
            ));
        }
        if max_batch_bytes == 0
            || max_batch_bytes > 16_777_216
            || max_batch_rows == 0
            || max_batch_rows > 16_384
            || max_line_chars == 0
            || max_line_chars > 8_388_608
            || max_record_bytes == 0
            || max_record_bytes > 33_554_432
        {
            return Err(PyValueError::new_err(
                "native parser bounds exceed supported limits or are zero",
            ));
        }
        let file = open_source(&path, source_handle)
            .map_err(|error| PyOSError::new_err(error.to_string()))?;
        let metadata = Metadata {
            host,
            log_type: if kind == "iis" {
                "iis".into()
            } else {
                log_type
            },
            source_path,
            source_file,
            file_sha256,
        };
        let schema = Arc::new(Schema::new(
            COLUMNS
                .iter()
                .map(|name| Field::new(*name, DataType::Utf8, true))
                .collect::<Vec<_>>(),
        ));
        Ok(Self {
            lines: Some(lines::Lines::new(file, path, max_line_chars)),
            metadata,
            kind,
            fields: None,
            schema,
            pending_row: None,
            pending_error: None,
            max_batch_bytes,
            max_batch_rows,
            max_record_bytes,
            max_integer_digits,
            done: false,
            error_count: 0,
            record_count: 0,
            scanned_lines: 0,
            scanned_bytes: 0,
        })
    }

    fn next_batch(&mut self, py: Python<'_>) -> PyResult<Option<NativeBatch>> {
        // No Python objects, Python callbacks or Arrow Python calls are touched
        // while detached. The returned batch owns all buffers independently.
        py.detach(|| self.read_batch())
            .map_err(Failure::into_python)
    }

    #[getter]
    fn error_count(&self) -> u64 {
        self.error_count
    }

    #[getter]
    fn record_count(&self) -> u64 {
        self.record_count
    }

    fn close(&mut self) {
        self.lines = None;
        self.pending_row = None;
        self.pending_error = None;
        self.done = true;
    }
}

impl NativeWebReader {
    fn next_row(&mut self) -> Result<RowOutcome, Failure> {
        if let Some(row) = self.pending_row.take() {
            return Ok(RowOutcome::Record(row));
        }
        let Some(line) = self.lines.as_mut().expect("open reader").next()? else {
            self.done = true;
            return Ok(RowOutcome::End);
        };
        self.scanned_lines += 1;
        self.scanned_bytes += line.len() as u64;
        if line.chars().all(lines::python_whitespace) {
            return Ok(RowOutcome::Skipped);
        }
        let row = if self.kind == "iis" {
            if let Some(fields) = line.strip_prefix("#Fields:") {
                self.fields = Some(parsers::IisLayout::new(fields)?);
                return Ok(RowOutcome::Skipped);
            }
            if line.starts_with('#') {
                return Ok(RowOutcome::Skipped);
            }
            if let Some(fields) = &self.fields {
                parsers::iis(&line, fields, self.max_integer_digits)?
            } else {
                None
            }
        } else {
            parsers::web(&line, self.max_integer_digits)?
        };
        if let Some(row) = row {
            return Ok(RowOutcome::Record(row));
        }
        self.error_count += 1;
        Ok(RowOutcome::Skipped)
    }

    fn read_batch(&mut self) -> Result<Option<NativeBatch>, Failure> {
        if let Some(error) = self.pending_error.take() {
            self.done = true;
            self.lines = None;
            return Err(error);
        }
        if self.done {
            return Ok(None);
        }
        let mut builders: Vec<StringBuilder> =
            (0..COLUMN_COUNT).map(|_| StringBuilder::new()).collect();
        let mut sizes = Vec::new();
        let mut bytes = 0;
        let initial_lines = self.scanned_lines;
        let initial_bytes = self.scanned_bytes;
        // Invalid-only input must still return to Python regularly, so signal
        // handling and cancellation do not wait for an entire file scan.
        while sizes.len() < self.max_batch_rows
            && self.scanned_lines - initial_lines < self.max_batch_rows as u64
            && self.scanned_bytes - initial_bytes < self.max_batch_bytes as u64
        {
            let row = match self.next_row() {
                Ok(RowOutcome::Record(row)) => row,
                Ok(RowOutcome::Skipped) => continue,
                Ok(RowOutcome::End) => break,
                Err(error @ Failure::Parse(_)) if !sizes.is_empty() => {
                    self.pending_error = Some(error);
                    break;
                }
                Err(error) => {
                    self.done = true;
                    self.lines = None;
                    return Err(error);
                }
            };
            let encoded = row.encoded_bytes(&self.metadata);
            if encoded > self.max_record_bytes {
                let error = Failure::Parse(format!(
                    "encoded log record exceeds {} bytes",
                    self.max_record_bytes
                ));
                if sizes.is_empty() {
                    self.done = true;
                    self.lines = None;
                    return Err(error);
                }
                self.pending_error = Some(error);
                break;
            }
            let row_bytes = row.buffer_bytes(&self.metadata);
            if !sizes.is_empty() && bytes + row_bytes > self.max_batch_bytes {
                self.pending_row = Some(row);
                break;
            }
            for (index, builder) in builders.iter_mut().enumerate() {
                builder.append_option(row.value(index, &self.metadata));
            }
            sizes.push(encoded as u64);
            bytes += row_bytes;
            self.record_count += 1;
            if bytes >= self.max_batch_bytes {
                break;
            }
        }
        if sizes.is_empty() && self.done {
            return Ok(None);
        }
        let arrays: Vec<ArrayRef> = builders
            .iter_mut()
            .map(|builder| Arc::new(builder.finish()) as ArrayRef)
            .collect();
        let batch = RecordBatch::try_new(self.schema.clone(), arrays)
            .map_err(|error| Failure::Parse(error.to_string()))?;
        Ok(Some(NativeBatch {
            batch,
            sizes: UInt64Array::from(sizes),
        }))
    }
}

fn open_source(path: &str, handle: Option<isize>) -> std::io::Result<File> {
    let Some(handle) = handle else {
        return File::open(path);
    };
    #[cfg(windows)]
    {
        use std::os::windows::io::{BorrowedHandle, RawHandle};
        // The adapter owns this verified handle for the reader's full lifetime.
        // Clone it, so dropping the reader never closes the Python file object.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(handle as RawHandle) };
        Ok(File::from(borrowed.try_clone_to_owned()?))
    }
    #[cfg(unix)]
    {
        use std::os::fd::BorrowedFd;
        let descriptor = i32::try_from(handle).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid source descriptor",
            )
        })?;
        let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
        Ok(File::from(borrowed.try_clone_to_owned()?))
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("API_VERSION", 1)?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add(
        "UnsupportedInputError",
        module.py().get_type::<UnsupportedInputError>(),
    )?;
    module.add_class::<NativeWebReader>()?;
    module.add_class::<NativeBatch>()?;
    module.add_class::<NativeArray>()?;
    Ok(())
}
