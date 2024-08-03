shared_object_name <- switch(Sys.info()[["sysname"]],
    Windows = "gtfsort.dll",
    Darwin = "libgtfsort.dylib",
    Linux = "libgtfsort.so"
)

shared_object_path <- file.path("target", "release", shared_object_name)

# Check if the shared object is present
if (!file.exists(shared_object_path)) {
    stop("The shared object '", shared_object_name, "' is missing.'")
}

dyn.load(shared_object_path)

message("loaded shared object '", shared_object_name, "'")

if (!(.Call("gtfsort_init_logger", "INFO")$success)) {
    stop("Failed to initialize logger.")
}

do_file_test <- function(input_file, output_file) {
    message("Running test with input file '", input_file, "' and output file '", output_file, "'")
    result <- .Call("gtfsort_sort_annotations", input_file, output_file, 4L)
    print(result)
    if (!result$success) {
        stop("Failed to sort '", input_file, "'.")
    }
}

do_string_test <- function(mode, input_string) {
    message("Running test with input string, length: ", nchar(input_string))

    output_buf <- c()
    output_fn <- function(buf) {
        output_buf <<- c(output_buf, buf)
    }

    result <- .Call("gtfsort_sort_annotations_string", mode, input_string, output_fn, 4L)
    print(result)
    if (!result$success) {
        stop("Failed to sort input string.")
    }
    paste0(output_buf, collapse = "")
}
