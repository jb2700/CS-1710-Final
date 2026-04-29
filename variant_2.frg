#lang forge

// this file shows the branch target injection variation of the Spectre attack

abstract sig Principal {}

one sig Victim, Attacker extends Principal {}

sig Address {}

one sig Memory {
    secretAddr: one Address 
}

sig State {
    owner: one Principal, 
    pc: one Address, // program control -> current instruction
    btb: pfunc Address -> Address, // branch target predictor -> need to poison this 
    cache: set Address,
    attackerKnowledge: set Address
}

// attacker "poisons" the btb by mapping an indirect branch to a malicious address, which
// causes CPU to speculatively jump to the malicious address 
pred poison_btb[s: State, victim_branch: Address, gadget: Address, next: State] {
    s.owner = Attacker

    next.btb = s.btb + (victim_branch -> gadget)

    next.pc = s.pc 
    next.cache = s.cache
    next.owner = Victim 
    next.attackerKnowledge = s.attackerKnowledge
}

// this is where the victim executes the code 
pred victim_executes[s: State, next: State] {
    s.owner = Victim 

    some s.btb[s.pc]

    // jump to the "poisoned" instruction by the attacker
    let predicted_target = s.btb[s.pc] | {
        // put the address into the cache
        next.cache = s.cache + Memory.secretAddr

        // rollback
        some safe_addr : Address | {
            next.pc = safe_addr
            safe_addr != predicted_target
        }
    }

  next.btb = s.btb
  next.owner = s.owner
  next.attackerKnowledge = s.attackerKnowledge

}

pred attacker_access[s: State, next: State] {
    s.owner = Victim
    next.cache = s.cache
    next.owner = Attacker

    (Memory.secretAddr in next.cache) => {
        next.attackerKnowledge = s.attackerKnowledge + Memory.secretAddr
    } else {
        next.attackerKnowledge = s.attackerKnowledge
    }
}

test expect {
    full_spectre_v2_attack: {
        some s0, s1, s2, s3: State | {
            no s0.cache
            no s0.btb

            some branch_addr, gadget_addr: Address | {
                poison_btb[s0, branch_addr, gadget_addr, s1]
                
                // Victim runs and hits that branch
                s1.pc = branch_addr
                victim_executes[s1, s2]
            }

            attacker_access[s2, s3]
            Memory.secretAddr not in s0.attackerKnowledge
            s0.owner = Attacker
            s1.owner = Victim
            s2.owner = Victim
            s3.owner = Attacker
            Memory.secretAddr in s3.attackerKnowledge
        }
    } is sat
}