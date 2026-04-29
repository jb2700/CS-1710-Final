# Project Overview
This project aims to formally model the Spectre vulnerability. Using the Forge framework, 
I am constructing a model of a simplified CPU pipeline to demonstrate how speculative 
execution and branch prediction can be exploited to leak data across architectural boundaries. 

# What is Spectre
Spectre is a CPU/hardware attack that takes advantage of a CPU's speculative execution. Speculative execution
is an optimization method where the CPU will predict the most likely path of a certain program and will
execute the instructions to decrease runtime. During this process, an attacker "tricks" the CPU into 
mispredicting a branch, causing it to speculatively load secret data into the cache. There are two variants 
of the Spectre attack, the first one relying on a conditional branch predictor and the second on relying on
a branch target injection. 

## Variant 1: Conditional Branch Predictor 
This variant tricks the CPU into looking past an index out of bounds error when for example indexing into
an array. The way the attacker does this is by calling a certain method many, many times in a row. Now after the 
100th time this method is called, the CPU tracks this and tries to do some optimization. By its logic the bounds check
is almost always going to be true, so it will try to just guess the bounds are correct and then access the array
without the check as they check has always been true for so many cases. This saves runtime as if the prediction is 
correct, the CPU is able to execute the code faster. Unfortunately, the attacker can take advantage of this and 
once they can "trick" the CPU into believing a bounds check will always be true and then passing in a huge index
that is way larger than the bounds of the array. Since the CPU is initially convinced that this index is ok, it will
speculatively execute this and pull the value into the cache. After it realizes that the bounds check actually fails,
it will try to roll back and clear the registers but it's already too late as the value the attacker is looking for
is already on the cache and the attacker can just query the cache to get the secret data. 

### Mini-Example 1: 
```c
if (user_index < array1_size) {   // CPU predicts this is TRUE to save time
    address = array1[user_index]; // Attacker provides a huge index
    temp = cache[address];        // Secret data is now pulled into cache
}
```

## Variant 2: Branch Target Injection
This variant tricks the CPU into jumping to the wrong instruction. The attacker does this through utilizing 
indirect jumps. Indirect jumps are jumps where the CPU doesn't have a fixed destination address, but instead looks up where to go next from a memory location or register. Because this lookup takes time, the CPU uses the Branch Target Buffer (BTB) to guess the destination. Similar to the previous variant, the attacker "poisons" the BTB by running their own code to convince the CPU that a specific jump should always go to a "gadget" address. When the victim eventually runs that same jump, the CPU speculatively executes the attacker's gadget in the victim's context. By the time the CPU realizes it's at the wrong address and "rolls back", the gadget has already pulled a secret value into the cache for the attacker to find.

### Mini-Example 2: 
```c
// Indirect jump
void (*func_ptr)(void); 

// 1. The attacker has already "poisoned" the BTB.
// 2. The CPU reaches this line and asks the BTB where to go.
// 3. The BTB says that it should go to the Gadget address
func_ptr(); 

// 4. The CPU speculatively jumps to the Gadget and runs it:
//    temp = cache[Memory.secretAddr]; 

// 5. The hardware finally calculates the REAL func_ptr, sees it's 
//    not the Gadget, and rolls back, but the cache is already leaked.
```

### How to run
Just run the variant_1.frg and variant_2.frg files and then you can correctly see the trace where the secret value is stolen. 