#homework table
PB16001696 金朔苇
##table
作业名称|发布时间|耗费时间|距截止期剩余时间|容易程度
|:--------:|:----------:|:----------:|:------------:|:----------:|
|OSH lab|3 days ago|1 days|8 days left|3|
|Deep Learning lab|5 days ago|3 days|12 days left|2|
|Mathmatics And Physics|3 days ago|2 days|6 days left|3|
|Mastering Bitcoin|2 days ago|1 days|30 days left|2|
|Linear Optimization|3 days ago|1 days|20 days left|3|

##Is it scheduable?

$$
\begin{align}
U & = \sum_{i=1}^{n} \frac{T_{\mathrm{cost}}(i)}{T\_{\mathrm{remains}}(i)} \\
& = \frac{1}{8}+\frac{3}{12}+\frac{2}{6}+\frac{1}{30}+\frac{1}{20}\\
& \approx 0.792
\end {align}
$$
we have $U \leq 1$ So the work can be finished

##the finished order of the work
1st should be the Mathmatics And Physics
2nd should be OSH lab
3rd should be Deep Learning lab
4th should be Linear Optimization
5th should be Mastering Bitcoin

##program exchange code
first should start to do your homework
save the return address of the main program into the register
###start to change to homework1
load the address of homework1 to pc
Some other son process may be called (if this happens, also save the return address into the register)
finish homework1
return to the father program


###start to change to homework2
load the address of homework2 to pc
Some other son process may be called
finish this homework
return to the father program

finish all the work



