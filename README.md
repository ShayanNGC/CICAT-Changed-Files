# CICAT-Changed-Files

## Summary
**For documentation on CICAT, please refer to [MITRE's CICAT repository.](https://github.com/mitre/CICAT)**

*Note: These changes are NOT associated with MITRE*

This repository contains CICAT files that were changed to support 2022 ATT&CK data. Included in this file are the revised generator and ATK folders, as well as an aditional example. The details of these folders, their contents, and the usage of this repository are presented below.

## Folders & Files
### generator
The generator folder contains all of the python programs needed for CICAT to generate scenarios. In this folder, the following files were changed to support 2022 ATT&CK data:
- afactory.py
- ifactory.py
- scenGEN.py
- SSoutput.py
- TACSequence.py

### ATK
This folder contains the modern ATT&CK data in the form of a JSON file. Data within this folder was gathered from MITRE's [ATT&CK v11.2 repository](https://github.com/mitre/cti/releases/tag/ATT%26CK-v11.2). The data from ATT&CK v11.2 was parsed through and formatted for use with CICAT. 

### example2
This folder contains an additional example that can be ran by CICAT. The network topology diagram was sourced from [here](https://tonymangan.wordpress.com/network-issues/uml-and-network-architecture-diagrams/). Labels and zones were added to provide CICAT with valid inputs. 

## Usage
To adapt CICAT to work with 2022 ATT&CK data, follow these steps:

1. Install CICAT
2. Replace the existing (CICAT-master > cicat >) generator folder with the generator folder in this repository
3. Replace the existing (CICAT-master > cicat > data >) ATK folder with the ATK folder in this repository
4. *(Optional)* Add the example2 folder into the (CICAT-master >) cicat folder

