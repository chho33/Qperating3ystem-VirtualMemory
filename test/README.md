# s21-hmwk4-team11
## Test
### Processes involved:
  vm_inspector.c: our main program to dump the page table entries of a process in given range.
  vm_inspector_loop: runs vm_inspector every second to capture the change caused by copy_on_write in the last case
  demo.c: a program that generates several cases for testing.
### Video demonstration
[Video demonstration](https://www.youtube.com/watch?v=QVOkitHgaHY)<br />
A brief video demonstrating our program that performs memory operations.
The memory operations includes: allocating heap memory but not using it, write-fault, read-fault followed by a write, write (without fault), and copy-on-write.
### Testing process break down
There are 6 cases in total, we also list read-fault case seperately. <br />
Case _: allocating heap memory without using it<br />
![image]()<br />
Explanation: <br />
As we can see,<br />
Case _: write-fault <br />
![image]()<br />
Explanation: <br />
As we can see,<br />
Case _: read-fault <br />
![image]()<br />
Explanation: <br />
As we can see,<br />
Case _: read-fault followed by a write<br />
![image]()<br />
Explanation: <br />
As we can see,<br />
Case _: write without fault<br />
![image]()<br />
Explanation: <br />
As we can see,<br />
Case _: copy-on-write<br />
![image]()<br />
Explanation: <br />
For this case, we let the child process sleep for 5 ms so that during this time we can still observe that the address stays the same with parent.<br />
After that, the printf function will trigger the change in address space.<br />
The function is as below,<br />
<p>
child = fork();
	if (child == 0) {
		sleep(5);
		*case6 = 2;
		printf("Child write: %#02lx at %#014lx\n", *case6, (unsigned long) case6);
		sleep(10);
	}
</p>
As we can see,<br />
