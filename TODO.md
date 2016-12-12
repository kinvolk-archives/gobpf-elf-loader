* Move "guessing code" to userspace
* Copy dialer listen() goroutine
    * Use LocalAddr() to find out the source port
* netns
    * check if IPv6 is supported, and use the previous field as netns?
    * de-reference all the pointers?
* modify bpf code to use offsets after we found them
* probably make this a separate program
