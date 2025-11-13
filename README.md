# CSCE 5550 Class Project
## Ransomware Research
This project is explicitly for the purpose of exploring how randomware is designed and mocking ransomware functonality safely to have a malicious application to test against.

# Requirements
This project was written and tested using: 
- [go 1.25.4](https://go.dev/doc/install)
- linux kernel version 6.17.7-arch1-1 (no link, you can just use any modern kernel)
- [GNU make 4.4.1](https://www.gnu.org/software/make/)

All other necessary software/libraries are included in the golang program includes, no external libraries should be necessary except for those included with modern Linux disributions.

Some optional, but otherwise useful tools commonly included in most Linux distros:
- find
- tree
- ls
- cat
### Fully Portable components:
- Attack component
- Filesystem Monitoring/Logging
- signature generation tool (a golang wrapper for sha-256 hashing of input files)
### Non-portable components:
- infection (requires Rubber Ducky)
- the active prevention component
### How To Run
1. Clone this repo
2. run `make build-all`
3. to run the differnet components you can either run them manually or use the Makefile
	- **attack**: `make run-attack`
		- if this does not work, run the attack binary in p1_attack while in the p1_attack folder, this will run the encryption on the folder "encrypt_me"
		
	- **decrypt**: the files, ensure you're still in the p1_attack folder, the private key is present, and run `./attack -d` 
	- **monitoring + prevention**: `make run-monitor-fanotify`, then run `make run-attack`
4. to test topen a second terminal window, in it navigate to the project folder
5. as a last resort, the attack and monitor applications use flags and respond to basic -h --help queries to list application usages.