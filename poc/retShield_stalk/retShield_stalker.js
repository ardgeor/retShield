

function inspectObject(object) 
{	
	console.log('inspecting object ' + object);
   	for(var key in object)
	{
		console.log(key)
   	}
}


function showStack(stack) 
{
	console.log("Showing stack: (size=" + stack.length + ")");
	   for(var key in stack)
	   {
		  console.log("\t" + key + ": " + stack[key]);
	   }
  }


function showCallInfo(dict, callStack) 
{
	var value;
	var count = 0;
  	var size = Object.keys(dict).length;
	console.log("------------------------------------------------------------------------------------------------");
	console.log("                       			Call info");
	console.log("------------------------------------------------------------------------------------------------");
	for(var key in dict) 
	{
		value = dict[key];
		console.log((count++) + "\tid=" + key + ":      (addr,esp,@ret,ebp) = (" + value + ")");
	}
	console.log("\n");
	console.log("------------------------------------------------------------------------------------------------");
	console.log("                       			Call stack");
	console.log("------------------------------------------------------------------------------------------------");
	showStack(callStack);
	console.log("\n");
}


function processInstruction(context) 
{
	var instruction = Instruction.parse(context.pc);
	var threadId = Process.getCurrentThreadId();
	var funcAddr;
	var retAddr;
	var callId;
	var processCall;

	funcAddr = context.pc;
	console.log(instructionIndent + "[thread " + threadId + "] " + funcAddr + " : " + instruction);
	processCall = isAddressInRange(funcAddr);

	if (threadContext[threadId][FOLLOW] == false) 
	{		
		return;
	}
	if (threadContext[threadId][FUNCTION_START_FLAG]) 
	{						
		if(!processCall){
			console.log("[*] Skipping processing for call to function " + funcAddr + ", address out of range");
			threadContext[threadId][FUNCTION_START_FLAG] = false;
			return;
		}

		retAddr = context.esp.readPointer();
		callId = threadContext[threadId][CALL_COUNTER];

		console.log("call," + threadContext[threadId][CALL_FROM] + "," + funcAddr 
			+ "," + Object.keys(threadContext[threadId][CALL_STACK]).length);

		if (funcAddr.toString() === exitAddr.toString()) 
		{
			console.log("Calling exit. Mark thread " + threadId + " to be unfollowed");
			threadContext[threadId][FOLLOW] = false;
			return;
		}

		// update thead context parameters
		threadContext[threadId][CALL_STACK].push(callId);
		threadContext[threadId][CALL_INFO][callId] = [funcAddr, retAddr];
		threadContext[threadId][CALL_COUNTER] = callId + 1;
		threadContext[threadId][FUNCTION_START_FLAG] = false;

		// showCallInfo(threadContext[threadId][CALL_INFO], threadContext[threadId][CALL_STACK])
	}

	if (instruction.mnemonic === 'call') 
	{
		threadContext[threadId][FUNCTION_START_FLAG] = true;
		threadContext[threadId][CALL_FROM] = context.pc;
	} else if (instruction.mnemonic === 'ret') 
	{		
		if(!processCall || Object.keys(threadContext[threadId][CALL_STACK]).length == 0)
		{
			return;
		}
		
		retAddr = context.esp.readPointer();
		callId = threadContext[threadId][CALL_STACK].pop();
		var storedFuncAddr = threadContext[threadId][CALL_INFO][callId][0];
		var storedRetAddr = threadContext[threadId][CALL_INFO][callId][1];

		console.log("ret," + context.pc + "," + retAddr + "," + (Object.keys(threadContext[threadId][CALL_STACK]).length+1));
		
		if (String(retAddr) !== String(storedRetAddr)) 
		{
			console.error("[!] Return address modified!");
			console.log("return from function at " + storedFuncAddr 
				+ " : \n\t(callId=" + callId + ")  \n\t(ret point=" + context.pc + ")  " 
				+ "\n\t(esp=" + context.esp + ", @ret=" + retAddr + ", ref @ret=" + storedRetAddr + ")");
			
			// showCallInfo(threadContext[threadId][CALL_INFO], threadContext[threadId][CALL_STACK])
			
			console.log("exit function address: " + exitAddr);
			ptr(context.esp.add(4)).writeInt(0x1); // place exit code on the previous position of the stack 
			context.esp.writePointer(ptr(exitAddr)); // place exit addr on top of the stack
			console.log("Calling exit. Mark thread " + threadId + " to be unfollowed");
			threadContext[threadId][FOLLOW] = false;			
		}

		delete threadContext[threadId][CALL_INFO][callId];
		// showCallInfo(threadContext[threadId][CALL_INFO], threadContext[threadId][CALL_STACK])
	} else if (instruction.mnemonic === 'sysenter') 
	{
		if(!processCall || Object.keys(threadContext[threadId][CALL_STACK]).length == 0)
		{
			return;
		}

		callId = threadContext[threadId][CALL_STACK].pop();
		delete threadContext[threadId][CALL_INFO][callId];
		retAddr = "kernelspace";
		console.log("ret," + context.pc + "," + retAddr + "," + (Object.keys(threadContext[threadId][CALL_STACK]).length+1));
	}
}


function initThreadContext(threadId)
{
	console.log("[*] Initializing thread [" + threadId + "]");
	threadContext[threadId] = {};
	
	threadContext[threadId][FUNCTION_START_FLAG] = false;
	threadContext[threadId][CALL_COUNTER] = 0;
	threadContext[threadId][CALL_STACK] = [];
	threadContext[threadId][CALL_INFO] = {};
	threadContext[threadId][CALL_FROM] = undefined;	
	threadContext[threadId][FOLLOW] = true;
}


function stalk() 
{	
	Process.enumerateThreads({
		onMatch: function (thread) 
		{
			threadIds.push(thread.id);
			console.log("Thread ID: " + thread.id.toString());
		},

		onComplete: function () 
		{
			threadIds.forEach(function (threadId) 
			{
				initThreadContext(threadId);
				Stalker.follow(threadId, 
				{				
					transform: function (iterator) {
						var instruction = iterator.next();
												
						do {							
							if (threadContext[threadId][FOLLOW] == false) 
							{
								console.log("Unfollowing thread " + threadId);
								Stalker.unfollow(threadId);
							}
							iterator.putCallout(processInstruction);	
							iterator.keep();
						} while ((instruction = iterator.next()) !== null);
					}
				});
			});
		}
	});
}


function isAddressInRange(addr) 
{
	var res = false;
	switch(se) 
	{
		case "00":
			res = true;
			break;
		case "01":
			if(addr <= endAddr) 
			{
				res = true;								
			}
			break;
		case "10":
			if(addr >= startAddr) 
			{
				res = true;								
			}
			break;
		case "11":
			if(addr >= startAddr && addr <= endAddr) 
			{
				res = true;								
			}
			break;
		default:
			throw new Error('/!\\ Invalid status for start/end addresses');
	}
	return res;
}


function processAddrRange() 
{
	if (startAddr !== undefined)
	{
		if (endAddr !== undefined)
		{
			se = "11";
			addrRange = "[" + startAddr + "," + endAddr + "]";			
		} else 
		{
			se = "10";
			addrRange = "[" + startAddr + ",end]";			
		}
	} else 
	{
		if (endAddr !== undefined)
		{
			se = "01";
			addrRange = "[start," + endAddr + "]";
		} else 
		{
			se = "00";
			addrRange = "[start,end]";					
		}
	}
}

// Constants	
const FUNCTION_START_FLAG = 400;
const CALL_COUNTER = 401;
const CALL_STACK = 402;
const CALL_INFO = 403;
const CALL_FROM = 404;
const FOLLOW = 405;
const instructionIndent = "\t\t\t\t\t\t\t\t\t\t";

// Global variables
var threadIds = [];
var threadContext = {};
var exitAddr = DebugSymbol.getFunctionByName("exit");
// ---------------------------- Configuration ----------------------------
var targetModuleName = "prog_32b";
var startOffset = 0x5BD;
var endOffset = 0x6CD; //0x62E;	
var targetModule = Process.findModuleByName(targetModuleName);
var targetModuleBaseAddr = ptr(targetModule.base);
var startAddr = targetModuleBaseAddr.add(startOffset);
var endAddr = targetModuleBaseAddr.add(endOffset);
// var startAddr;
// var endAddr;
var restrictProgramScope = false;
// -----------------------------------------------------------------------
var addrRange;
var se;


console.log("[*] Target module '" + targetModule.name + "' loaded at address " + targetModuleBaseAddr);
processAddrRange(); // fill addrRange and se

stalk();