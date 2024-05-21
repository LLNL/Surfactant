# CLI Usage
The surfactant cli interface allows users to easily and quickly find, add, and edit entires within a given SBOM.
Some functionality we support include:
- Specify a file to either find, add, or edit it's entry in a given SBOM
- Fix up path prefixes, i.e. installPath or containerPath
- Add relationships 

## surfactant cli find
The **cli find** command allows users to find specific entries within a SBOM. This will allow users to do a few things
- Verify entries exist within the sbom
- Manually inspect one or more related entries with an SBOM for errors or bad formatting
- Provide a subset of entries to supply to the cli edit or cli add command.

### Example 1: Find Exact Matches
```bash
surfactant cli find sbom.json --filename foo.exe  
{  
"UUID": 123,  
"filename": foo.exe,  
"sha256": <hash>,
"installPath": ["C:/Users/Test/Downloads/"]  
}  
surfactant cli find --UUID 456  
{
"UUID": 456,
"filename": test.exe,
"sha256": <hash>,
"installPath": ["C:/Users/Test/Documents/"]
}
```
### Example 2: Find a Partial Matches
```bash
surfactant cli find --filename *.exe  
{  
"UUID": 123,  
"filename": foo.exe,  
"sha256": <hash>,
"installPath": ["C:/Users/Test/Downloads/"]  
}, 
{  
"UUID": 456,  
"filename": test.exe,  
"sha256": <hash>,
"installPath": ["C:/Users/Test/Documents/"]  
} 
```
```bash
surfactant cli find --installpath C:/Users/Test/Downloads/
{  
"UUID": 123,  
"filename": foo.exe,  
"sha256": <hash>  
"installPath": ["C:/Users/Test/Downloads/"]
}
```
### Example 3: Find by File
Note: File matches are found by hash matching, not filename matches.
```bash
surfactant cli find --file foo.exe  
{  
"UUID": 123,  
"filename": foo.exe,  
"sha256": <hash>,
"installPath": ["C:/Users/Test/Downloads/"]  
}
```

## surfactant cli add
The **cli add** command will allow users to easily manually add entries to an SBOM. This command should allow users to do a few things:
- Add key value pairs to existing SBOM entries
- Add whole new entries to sbom

```bash
surfactant cli add --relationship "{xUUID:"123",yUUID:456, "relationship: "Uses"}" 
```
```bash
surfactant cli add --entry "{UUID:"123",filename:"test.exe", "sha256": "3423csdlkf13048kj"}" sbom.json 
```
```bash
surfactant cli add --file test.exe sbom.json 
```