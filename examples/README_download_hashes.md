# Download Files from VirusTotal using Hash List

This CLI tool allows you to download multiple files from VirusTotal using a text file containing hashes.

## Usage

```bash
cargo run --example download_hashes_from_file -- --help
```

## Basic Examples

```bash
# Download files using hashes from sample_hashes.txt (public tier)
cargo run --example download_hashes_from_file -- \
  --input sample_hashes.txt \
  --output ./downloads \
  --api-key YOUR_API_KEY

# Download files with JSON analysis reports
cargo run --example download_hashes_from_file -- \
  --input sample_hashes.txt \
  --output ./downloads \
  --reports \
  --reports-dir ./analysis_reports \
  --api-key YOUR_API_KEY

# Premium tier with concurrent downloads
cargo run --example download_hashes_from_file -- \
  --input sample_hashes.txt \
  --output ./downloads \
  --api-key YOUR_API_KEY \
  --tier premium \
  --concurrency 10

# Maximum performance with reports (premium only)
cargo run --example download_hashes_from_file -- \
  --input large_hash_list.txt \
  --output ./downloads \
  --reports \
  --api-key YOUR_API_KEY \
  --tier premium \
  --concurrency 20 \
  --skip-errors

# Only download JSON reports (useful for non-downloadable files)
cargo run --example download_hashes_from_file -- \
  --input hashes.txt \
  --reports-only \
  --reports-dir ./analysis_reports \
  --api-key YOUR_API_KEY \
  --tier premium \
  --concurrency 10
```

## Command-line Options

- `-i, --input <FILE>`: Path to text file containing hashes (required)
- `-o, --output <DIR>`: Output directory for downloaded files (default: ./downloads)
- `-k, --api-key <KEY>`: VirusTotal API key (can also use VTI_API_KEY env variable)
- `-t, --tier <TIER>`: API tier - "public" or "premium" (default: public)
- `-c, --concurrency <N>`: Number of concurrent downloads for premium tier (default: 5, max: 20)
- `-r, --reports`: Download and save JSON analysis reports for each file
- `--reports-only`: Only download JSON reports, skip binary file downloads
- `--reports-dir <DIR>`: Directory for JSON reports (default: ./reports)
- `-s, --skip-errors`: Continue downloading even if some hashes fail
- `-v, --verbose`: Enable verbose output

## Input File Format

The input text file should contain one hash per line. The tool supports:
- MD5 hashes
- SHA-1 hashes  
- SHA-256 hashes

Lines starting with `#` are treated as comments and ignored.
Empty lines are also ignored.

Example input file:
```
# Sample hashes
44d88612fea8a8f36de82e1278abb02f
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
3395856ce81f2b7382dee72602f798b642f14140
```

## Environment Variables

You can set your API key as an environment variable:
```bash
export VTI_API_KEY="your_api_key_here"
cargo run --example download_hashes_from_file -- -i hashes.txt
```

## Features

- **Concurrent Downloads**: Premium tier users can download multiple files in parallel (up to 20)
- **JSON Analysis Reports**: Optionally download complete VirusTotal analysis reports in JSON format
- **Automatic Rate Limiting**: Public tier uses sequential downloads to respect rate limits
- **Hash-based Filenames**: Saves files using their hash as filename (e.g., `44d88612fea8a8f36de82e1278abb02f.bin`)
- **Organized Output**: Separate directories for binary files and JSON reports
- **Progress Tracking**: Real-time progress indicator for all downloads
- **Error Recovery**: Option to skip failed downloads and continue
- **Verbose Mode**: Detailed output for debugging
- **Smart Defaults**: Automatically optimizes based on your API tier

## JSON Analysis Reports

When using the `--reports` flag, the tool downloads complete VirusTotal analysis reports for each file. These reports include:

- Detection results from all antivirus engines
- File metadata (size, hashes, file type, etc.)
- Behavioral analysis results
- YARA rule matches
- Submission history
- Community votes and comments

Reports are saved as `{hash}.json` in the reports directory, making it easy to correlate with the downloaded files.

## Output Structure

```
./downloads/                    # Binary files
├── 44d88612fea8a8f36de82e1278abb02f.bin
├── 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.bin
└── 3395856ce81f2b7382dee72602f798b642f14140.bin

./reports/                      # JSON analysis reports (if --reports used)
├── 44d88612fea8a8f36de82e1278abb02f.json
├── 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.json
└── 3395856ce81f2b7382dee72602f798b642f14140.json
```

## Error Handling

By default, the tool will stop on the first error. Use `--skip-errors` to continue downloading remaining files even if some fail.

The tool handles various error scenarios gracefully:
- **Non-downloadable files**: Files that are too large or restricted will be skipped with a warning
- **Decode errors**: Server-side issues are detected and reported clearly
- **Permission errors**: Files requiring special access show appropriate messages
- **Temporary failures**: Network or server errors are identified
- **Fallback to reports**: When files can't be downloaded but reports are available, the tool will still save the JSON report

When using `--reports` flag, the tool will attempt to save the JSON report even if the binary file download fails, ensuring you get as much data as possible.

## Requirements

- Valid VirusTotal API key
- Sufficient API quota for downloading files
- Network connectivity to VirusTotal API