"use strict";


const mainThread = Process.getCurrentThreadId();
console.log("[*] Setting hooks");

Interceptor.attach(Module.getExportByName(null, 'strcpy'), {
    onEnter(args) {      
        console.log("[=>] strcpy");
        console.log("args[0]                            : " + args[0]);
        console.log("args[1]                            : " + args[1]);
        var a1 = Memory.readCString(args[1]);        
        console.log("*args[1]                           : " + a1);
        var esp = this.context.esp;
        this.bufferPtr = Memory.readPointer(esp.add(4));
        this.ebp = this.context.ebp;
        this.callerRetAddrPtr = this.ebp.add(4); 
        this.originalCallerRetAddr = Memory.readPointer(this.callerRetAddrPtr);
        console.log("esp                                : " + esp);
        console.log("ebp                                : " + this.ebp);
        console.log("bufferAddr                         : " + this.bufferPtr);
        console.log("&callerRetAddr                     : " + this.callerRetAddrPtr);
        console.log("callerRetAddr                      : " + this.originalCallerRetAddr); 
        
        console.log("\nView of Stack: ");
        console.log(hexdump(esp, {
            offset: 0,
            length: 0x80,
            header: false,
            ansi: true
          }));

        console.log("\n * strcpy * \n");
    },
    onLeave (retval) {        
        var callerRetAddrBeforeRet = Memory.readPointer(this.callerRetAddrPtr);
        
        console.log("esp                                : " + this.context.esp);
        
        console.log("\nView of Stack: ");
        console.log(hexdump(this.context.esp, {
            offset: 0,
            length: 0x80,
            header: false,
            ansi: true
          }));
        
        console.log("\n");
        console.log("original caller return address     : " + this.originalCallerRetAddr); 
        console.log("caller return address before 'ret' : " + callerRetAddrBeforeRet); 

        if (this.originalCallerRetAddr.toString() !== callerRetAddrBeforeRet.toString()){
            console.error("\n/!\\ Stack buffer overflow detected! Aborting program...");
            Thread.sleep(0.05);
            exit(1);
        } else {
            console.log("Ok");
        }

        console.log("[<=] strcpy");
    }    
  });


console.log("[+] Done!");

var exitPtr = Module.findExportByName(null, "exit");
var exit = new NativeFunction(exitPtr, 'void', ['int']);

