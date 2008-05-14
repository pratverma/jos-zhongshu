#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>


// Choose a user environment to run and run it.
void
sched_yield(void)
{
	// Implement simple round-robin scheduling.
	// Search through 'envs' for a runnable environment,
	// in circular fashion starting after the previously running env,
	// and switch to the first such environment found.
	// It's OK to choose the previously running env if no other env
	// is runnable.
	// But never choose envs[0], the idle environment,
	// unless NOTHING else is runnable.

	// LAB 4: Your code here.
	//cprintf("begin sched yield,curenv:%08x,&envs[0]:%08x\n",curenv,&envs[0]);
	
	uint32_t i;
	uint32_t start = curenv ? (ENVX(curenv->env_id) + 1)%NENV : 0;

	for(i = 0; i < NENV;i++)
	{
		uint32_t index = (start + i)%NENV;
		if(index == 0)
		       	continue;
		else if(envs[index].env_status == ENV_RUNNABLE)
		{
			//cprintf("env_run:run envs[%08x]\n",index);
			//cprintf("env_tf:%08x\n",envs[index].env_tf);
			env_run(&envs[index]);
			return;
		}
			
	}	
	// Run the special idle environment when nothing else is runnable.
	if (envs[0].env_status == ENV_RUNNABLE)
		env_run(&envs[0]);
	else {
		cprintf("Destroyed all environments - nothing more to do!\n");
		while (1)
			monitor(NULL);
	}
}
