# Usage

## Identify Sample File

In order to test out surfactant, you will need a sample file/folder. If you don't have one on hand, you can download and use the portable .zip file from https://github.com/ShareX/ShareX/releases or the Linux .tar.gz file from https://github.com/GMLC-TDC/HELICS/releases. Alternatively, you can pick a sample from https://lc.llnl.gov/gitlab/cir-software-assurance/unpacker-to-sbom-test-files

## Running Surfactant

```bash
$  surfactant generate [OPTIONS] CONFIG_FILE SBOM_OUTFILE [INPUT_SBOM]
```

**CONFIG_FILE**: (required) the config file created earlier that contains the information on the sample\
**SBOM OUTPUT**: (required) the desired name of the output file\
**INPUT_SBOM**: (optional) a base sbom, should be used with care as relationships could be messed up when files are installed on different systems\
**--skip_gather**: (optional) skips the gathering of information on files and adding software entires\
**--skip_relationships**: (optional) skips the adding of relationships based on metadata\
**--skip_install_path**: (optional) skips including an install path for the files discovered. This may cause "Uses" relationships to also not be generated\
**--recorded_institution**: (optional) the name of the institution collecting the SBOM data (default: LLNL)\
**--output_format**: (optional) changes the output format for the SBOM (given as full module name of a surfactant plugin implementing the `write_sbom` hook)\
**--input_format**: (optional) specifies the format of the input SBOM if one is being used (default: cytrics) (given as full module name of a surfactant plugin implementing the `read_sbom` hook)\
**--help**: (optional) show the help message and exit


## Merging SBOMs

TODO: Instructions on how to merge
