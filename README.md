# Prefix Validator

A comprehensive tool for extracting and validating IP prefixes from various file formats.

## Features

- **Extract IP Prefixes** from multiple file formats:
  - Text files (.txt, .log, .conf, .ini)
  - CSV files (.csv)
  - Excel files (.xls, .xlsx, .xlsm)
  - Word documents (.docx)
  - PDF files (.pdf)
  - JSON files (.json)
  - XML files (.xml, .html, .htm)

- **Validate IP Prefixes** using routinator api https://routinator.docs.nlnetlabs.nl/en/stable/
  - Fast and reliable API-based validation
  - Checks validity against specified ASN
  - Returns detailed validation status

- **Complete Workflow**
  - Extract prefixes from source files
  - Validate extracted prefixes
  - Generate comprehensive reports

## Installation

1. Clone this repository:
```
git clone https://github.com/itzn2003/prefix_validator.git
cd prefix_validator
```

2. Create a virtual environment (recommended):
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

## Usage

### Running the Complete Workflow

To extract and validate IP prefixes in a single operation:
- replace `input_file.txt` wiht path to your actual input file
- replace `XXX` with actual ASN you are using

```bash
python -m src.validator input_file.txt --asn XXX --output-dir ./results
```

Options:
- `--asn` (required): Autonomous System Number for validation
- `--output-dir`: Directory to save output files (default: same directory as input file)
- `--batch-size`: Number of IPs to process before pause (default: 10) NOTE: values larger than 20-30 may throttle performance for lower end machines
- `--delay`: Delay in seconds between batches (default: 1.0) NOTE: lower values than 0.5 may cause errors

### Using Individual Components

#### Extract IP Prefixes

```bash
python -m src.ip_extractor path/to/file.txt -o extracted_prefixes.csv
```

#### Validate IP Prefixes

```bash
python -m src.ip_validator path/to/ip_list.txt --asn XXX -o validation_results.csv
```

## Output Files

The tool generates three output files:
1. `*_extracted_prefixes.csv` - Contains all extracted IP prefixes with context
2. `*_validated_prefixes.csv` - Contains validation results for each prefix
3. `*_combined_results.csv` - Combines extraction and validation data

## Validation Status

The API returns one of the following statuses:

- **valid** - The announcement matches a ROA and is valid
- **invalid_asn** - There is a ROA with the same (or covering) prefix, but a different ASN
- **invalid_length** - The announcement's prefix length is greater than the ROA's maximum length
- **unknown** - No ROA found for the announcement
- **error** - An error occurred during validation

## Requirements

- Python 3.7+
- Dependencies:
  - pandas
  - openpyxl
  - python-docx
  - pdfplumber
  - PyPDF2
  - chardet
  - requests

## Contact

Feel free to reach out to me via either of my email addresses:
- zatoru2003@proton.me
- it.zn.203@gmail.com