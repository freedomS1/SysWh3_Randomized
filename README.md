#  SysWh3_Randomized

------

**Author: https://github.com/xiaoyaoxianj**

This project is based on  [SysWispers-FuntionRandomizer](https://github.com/nick-frischkorn/SysWhispers-FunctionRandomizer) , which adds variable obfuscation on top of the original, and can customize the length of the variable.

I recommend deleting unnecessary content from the [Syswh3-generated files](https://github.com/klezVirus/SysWhispers3) before using the script. Use the following tips to improve your efficiency.

There are some variables in the project that cannot be easily replaced and can be implemented directly using renaming

![](.\Syswh3_Randomized\bug.png)

#### Tips:

 Here are some useful regular expressions to help us use in VSstudio(Ctrl + H)

#### Delete comments in all // modes

```
^[\t]*//[^\n]*\n
```

#### Delete all empty lines

```
^(?([^\r\n])\s)*\r?$\r?\n
```

#### Delete comments from all asm files

```
;.* ---> \n
```

#### Usage

```
python Syswh3_Randomized.py -l 6 xiaoyaoj.c xiaoyaoj.asm xiaoyaoj.h
```

#### Help

![](.\Syswh3_Randomized\Syswh3_Randomizd.png)

