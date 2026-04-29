#lang forge

open "variant_2.frg"

test expect {
    poison_btb_adds_mapping: {
        some s, next: State, b, g: Address | {
            poison_btb[s, b, g, next]
            (b -> g) not in next.btb
        }
    } is unsat

    poison_btb_switches_context: {
        some s, next: State, b, g: Address | {
            poison_btb[s, b, g, next]
            s.owner = Attacker
            next.owner = Victim
        }
    } is sat

    poison_btb_does_not_leak: {
        some s, next: State, b, g: Address | {
            no s.cache
            poison_btb[s, b, g, next]
            Memory.secretAddr in next.cache
        }
    } is unsat
}

test expect {
    victim_requires_btb_entry: {
        some s, next: State | {
            no s.btb[s.pc] 
            victim_executes[s, next]
        }
    } is unsat

    victim_rolls_back_pc: {
        some s, next: State | {
            victim_executes[s, next]
            next.pc = s.btb[s.pc]
        }
    } is unsat

    victim_leaves_cache_trace: {
        some s, next: State | {
            victim_executes[s, next]
            Memory.secretAddr in next.cache
        }
    } is sat
}

test expect {
    knowledge_requires_cache: {
        some s0,s1,s2,s3 : State | {
            some branch_addr, gadget_addr: Address | {
                poison_btb[s0, branch_addr, gadget_addr, s1]

                s1.pc = branch_addr
                victim_executes[s1, s2]
            }
            attacker_access[s2, s3]
            Memory.secretAddr not in s2.cache
            Memory.secretAddr in s3.attackerKnowledge
        }
    } is unsat
}