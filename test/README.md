# s21-hmwk4-team11
## Test
### Processes involved:
  vm_inspector.c: our main program to dump the page table entries of a process in given range.<br />
  vm_inspector_loop: runs vm_inspector every second to capture the change caused by copy_on_write in the last case described below.<br />
  demo.c: a program that generates several cases for testing.<br />
### Video demonstration
[Video demonstration](https://www.youtube.com/watch?v=QVOkitHgaHY)<br />
A brief video demonstrating our program that performs memory operations.<br />
The memory operations includes: allocating heap memory but not using it, write-fault, read-fault followed by a write, write (without fault), and copy-on-write.<br />
### Testing process break down
There are 6 cases in total, we also list read-fault case seperately. <br />
First of all, all testing cases are described in demo.c, and we trigger the next step in the program by getchar() so that there's only one pid involved in the testing process(2549 in our case shown below).<br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture2.PNG)<br />

Case _: allocating heap memory without using it<br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture1.PNG)<br />
Get the starting address of the first case.
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture3.PNG)<br />
Explanation: <br />
As we can see, we have the address but there's no physical address with respect to it for that we didn't use it.<br />
Case _: write-fault <br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture4.PNG)<br />
In the pic, between second and third line, we trigger getchar() once already.
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture5.PNG)<br />
Explanation: <br />
As we can see, the address changed in the screenshot for that a write fault was triggered on purpose.<br />
Case _: read-fault <br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture6.PNG)<br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture7.PNG)<br />
Explanation: <br />
As we can see,<br />
Case _: read-fault followed by a write<br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture8.PNG)<br />
![image](https://github.com/W4118/s21-hmwk5-team11/blob/master/test/screenshots/Capture9.PNG)<br />
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
child = fork();<br />
	if (child == 0) {<br />
		sleep(5);<br />
		*case6 = 2;<br />
		printf("Child write: %#02lx at %#014lx\n", *case6, (unsigned long) case6);<br />
		sleep(10);<br />
	}<br />
</p>
As we can see,<br />
