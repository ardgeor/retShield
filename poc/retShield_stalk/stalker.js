'use strict';

// https://www.youtube.com/watch?v=sBcLPLtqGYU

Process.enumerateThreadsSync().forEach(function (thread) {
	Stalker.follow(thread.id, {
		transform: function(iterator) {
			var instruction;
			var addr;
			while((instruction = iterator.next()) !== null) {
				addr = instruction.address;
				console.log(addr + " : " + instruction);
				iterator.keep();
			}
		}
	});
});
