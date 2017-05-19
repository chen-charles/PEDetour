PEDetour
========
modify binary Portable Executable to hook its export functions  

## Dependencies

This project uses *Capstone* disassembly framework and *Keystone* assembly framework.  
They will be included and compiled by *prerequisite.bat* and CMake.  
Information is available at [Capstone](http://www.capstone-engine.org) and [Keystone](http://www.keystone-engine.org).  

## Compile
This project uses CMake for compiliation.    
If you have *bash* enabled, run *prerequisite.bat* to automatically download capstone/keystone.  
Then,  
```
mkdir -p build && cd build && cmake .. && make && cd ..
```
Note: Visual Studio 2017 supports CMake projects as folders.  

## License

[Version 3 of the GNU General Public Licence (GPLv3)](https://github.com/chen-charles/PEDetour/blob/master/LICENSE)  

## v2.0 info
* re-designed  
* instead of working with in-place modifications in v1.0, fully take the input apart and then put all parts together  
* supports insertion (which emulates extension)  
* x86 --- in progress  
* x86_64 --- in progess  
* plans to support executable-loading-stage-hooking (act as an executable loader which could then load hook-ed kernel32.dll and other restricted ones)  
