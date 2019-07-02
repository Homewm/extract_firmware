#!/bin/bash

# setting texlive
export MANPATH=${MANPATH}:/usr/local/texlive/2017/texmf-dist/doc/man
export INFOPATH=${INFOPATH}:/usr/local/texlive/2017/texmf-dist/doc/info
export PATH=${PATH}:/usr/local/texlive/2017/bin/x86_64-linux

FIRM_PATH="$1"
EXTRACT_PATH="$2"
TROMMEL_PATH="/usr/local/trommel"
DECOMPRESS_DEEPTH=10

cur_dir=`pwd`
FIRM_NAME="${FIRM_PATH##*/}"
FIRM_DIR="${FIRM_PATH%/*}"

if [ ! -f $FIRM_PATH ];then
    echo "must assign a firmware path"
    exit
fi

[ -d $FIRM_DIR ] && cd $FIRM_DIR

binwalk -e -M -r -q --depth=$DECOMPRESS_DEEPTH "$FIRM_NAME" -C $EXTRACT_PATH/

if [ ! -d $EXTRACT_PATH/_"${FIRM_NAME}".extracted ];then
    touch $EXTRACT_PATH/_"${FIRM_NAME}"_failed
    exit
fi

cd $EXTRACT_PATH/
tree -J _"${FIRM_NAME}".extracted > ./_"${FIRM_NAME}"_tree.json
cd -

cd $EXTRACT_PATH/
tar zcvf _"${FIRM_NAME}".extracted.tar.gz _"${FIRM_NAME}".extracted
cd -

echo  "固件名:$FIRM_NAME" >>$EXTRACT_PATH/_"${FIRM_NAME}"_abstract

FIRM_MD5=$(md5sum "$FIRM_NAME"|awk '{print $1}')
echo "固件MD5:$FIRM_MD5" >>$EXTRACT_PATH/_"${FIRM_NAME}"_abstract

FIRM_INST=$(file `find $EXTRACT_PATH/_"${FIRM_NAME}".extracted/ -type f`|grep ELF|cut -d: -f2|sed 's/^[[:space:]]*//'|awk -F, '{print $2}'|sort|uniq |sort -nr|head -n1|sed 's/ //')
echo "指令集架构:$FIRM_INST" >>$EXTRACT_PATH/_"${FIRM_NAME}"_abstract

FIRM_SIZE=$(ls -lh "$FIRM_NAME"|awk '{print $5}')
echo "固件大小:$FIRM_SIZE" >>$EXTRACT_PATH/_"${FIRM_NAME}"_abstract

PKG_SIZE=$(ls -lh $EXTRACT_PATH/_${FIRM_NAME}.extracted.tar.gz |awk '{print $5}')
echo "固件解压包大小:$PKG_SIZE" >>$EXTRACT_PATH/_"${FIRM_NAME}"_abstract

#transportTxtToPdf
#定义待分析binwalk提取后的文件
analyseDir="${EXTRACT_PATH}/_"${FIRM_NAME}".extracted"

#定义输出文件
outputfile=${FIRM_NAME%.*}

#调用trommel分析工具
cd $TROMMEL_PATH
python trommel.py -p $analyseDir -o $outputfile >/dev/null 2>&1

#定义子文件标题
title1='敏感关键字'
title2='曾曝过漏洞的组件以及公开的攻击模块'
title3='口令文件或关键字'
title4='SSH/SSL相关文件或关键字'
title5='IP地址、URL以及email字符串'
title6='配置文件'
title7='数据库文件'
title8='黑名单中的二进制文件'
title9='/opt目录下的所有文件'
title10='shell脚本'
title11='web组件'
title12='与web相关的敏感关键字以及脚本函数'
title13='安卓APK文件，定位APK文件中的敏感词以及APK的权限'

tmpPath=${analyseDir}Dirs

#shell脚本功能扩充
#获取无.sh后缀名但文件首行是*sh的文件
for x in `find $analyseDir -type f`
do
    isShell=`sed -n '1p' $x|grep -a "^#!"|grep -a "sh$"|wc -l`
    if [ $isShell -eq 1 ];then
        binaryShellpath=${x##*extracted/}
        binaryShellName=${x##*/}
        case $binaryShellName in
            ".bashrc"|"rcS")
                echo ${binaryShellName}"(启动脚本)" \& "./"$binaryShellpath  >>$tmpPath/tmpfile10
                ;;
            *)
                echo $binaryShellName \& "./"$binaryShellpath  >>$tmpPath/tmpfile10
                ;;
        esac
    fi
done

#添加固件名，MD5 ，指令集架构，固件大小和解压包大小信息
sed -i "1i 固件名:${FIRM_NAME}\n\n 固件MD5:${FIRM_MD5}\n\n 指令集架构:${FIRM_INST}\n\n 固件大小:${FIRM_SIZE}\n\n 固件解压包大小:${PKG_SIZE}\n\n" $tmpPath/tmpfile0


#拼接
for((i=0;i<=13;i++))
do
    if [ "$i" -gt 0  ];then
        #临时文件去重排序
        sort -u $tmpPath/tmpfile$i -o $tmpPath/tmpfile$i
        sed -i 's/$/\\\\\\\\/g' $tmpPath/tmpfile$i
        sed -i '1d' $tmpPath/tmpfile$i
        bug_num=`cat $tmpPath/tmpfile$i|wc -l`
        #sed -i "1i(${bug_num}项)\n" $tmpPath/tmpfile$i

        title=title${i}
        eval subtitle=$(echo \$$title)
        echo "\\section{${subtitle}(${bug_num}项)}" >> $outputfile
        #创建表格
        case "$i" in
            "1")
                sed -i '1i 关键字 & 文件路径 & 文件类型 & 出现频次\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{2cm}|p{8.6cm}|p{1.2cm}|p{1.2cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "2")
                componentNum=`grep "^AAAA" $tmpPath/tmpfile$i|wc -l`
                #fileRowNum=`cat $tmpPath/tmpfile$i|wc -l`
                #attrackModeNum=$[$fileRowNum-$attrackModeNum]
                sed -i 's/^AAAA//g' $tmpPath/tmpfile$i
                #转义漏洞描述中的部分句子
                sed -i 's/\%/\\\\%/g' $tmpPath/tmpfile$i
                sed -i 's/&T/\\\\&/g' $tmpPath/tmpfile$i
                #先插中间后插头尾
                insertMid=$[$componentNum+1]
                sed -i "${insertMid}i\\\\\\\\\\\\hline\n\\\\\\\\\\\\end{longtable}\n\\\\\\\\\\\\end{center}\n\\\\\\\\\\\\makeatletter\\\\\\\\\\\\def\\\\\\\\\\\\@captype{table}\\\\\\\\\\\\makeatother\n\\\\\\\\\\\\scriptsize\n\\\\\\\\\\\\begin{center}\n\\\\\\\\\\\\begin{longtable}{|p{3cm}|p{10.9cm}|}\n\\\\\\\\\\\\hline\n 漏洞编号 & 攻击模块\\\\\\\\\\\\\\\\\\\\\\\\hline" $tmpPath/tmpfile$i

                sed -i '1i 组件名 & 漏洞编号 & 漏洞描述 \\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{1.5cm}|p{2.2cm}|p{9.7cm}|}\n\\\\\hline' $tmpPath/tmpfile$i

                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "3")
                kwNum=`grep "^zzzz" $tmpPath/tmpfile$i|wc -l`
                fileRowNum=`cat $tmpPath/tmpfile$i|wc -l`
                commandNum=$[$fileRowNum-$kwNum]
                sed -i 's/^zzzz//g' $tmpPath/tmpfile$i
                #先插中间后插头尾
                insertMid=$[$commandNum+1]
                sed -i "${insertMid}i\\\\\\\\\\\\hline\n\\\\\\\\\\\\end{longtable}\n\\\\\\\\\\\\end{center}\n\\\\\\\\\\\\makeatletter\\\\\\\\\\\\def\\\\\\\\\\\\@captype{table}\\\\\\\\\\\\makeatother\n\\\\\\\\\\\\scriptsize\n\\\\\\\\\\\\begin{center}\n\\\\\\\\\\\\begin{longtable}{|p{3cm}|p{10.9cm}|}\n\\\\\\\\\\\\hline\n 关键字 & 文件路径\\\\\\\\\\\\\\\\\\\\\\\\hline" $tmpPath/tmpfile$i

                sed -i '1i 文件名 & 文件路径 \\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{10.9cm}|}\n\\\\\hline' $tmpPath/tmpfile$i

                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "4")
                fileNum=`grep "^AAAA" $tmpPath/tmpfile$i|wc -l`
                sed -i 's/^AAAA//g' $tmpPath/tmpfile$i
                #先插中间后插头尾
                insertMid=$[$fileNum+1]
                sed -i "${insertMid}i\\\\\\\\\\\\hline\n\\\\\\\\\\\\end{longtable}\n\\\\\\\\\\\\end{center}\n\\\\\\\\\\\\makeatletter\\\\\\\\\\\\def\\\\\\\\\\\\@captype{table}\\\\\\\\\\\\makeatother\n\\\\\\\\\\\\scriptsize\n\\\\\\\\\\\\begin{center}\n\\\\\\\\\\\\begin{longtable}{|p{2cm}|p{8.6cm}|p{1.2cm}|p{1.2cm}|}\n\\\\\\\\\\\\hline\n SSH关键字 & 文件路径 & 文件类型 & 出现频次 \\\\\\\\\\\\\\\\\\\\\\\\hline" $tmpPath/tmpfile$i

                sed -i '1i 文件名 & 文件类型 & 文件路径 \\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{2cm}|p{8.4cm}|}\n\\\\\hline' $tmpPath/tmpfile$i

                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "5")
                sed -i 's/\%/\\\\%/g' $tmpPath/tmpfile$i
                sed -i 's/&T/\\\\&/g' $tmpPath/tmpfile$i
                sed -i '1i 字符串类型 & 属性值 & 文件类型 & 文件路径\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{1.2cm}|p{2.9cm}|p{1.2cm}|p{7.7cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "6"|"7"|"8"|"11")
                sed -i '1i 文件名 & 类型 & 文件路径\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{2cm}|p{8.4cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "9")
                sed -i '1i 类型 & 文件路径\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{10.9cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "10")
                sed -i '1i 脚本名 & 脚本路径\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{10.9cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;

            "12")
                sed -i '1i 关键字/脚本函数 & 文件路径 & 文件类型 & 出现频次\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{7.6cm}|p{1.2cm}|p{1.2cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;
            "13")
                sed -i '1i 类型 & 文件路径 & 相关内容\\\\\\\\\\\\hline' $tmpPath/tmpfile$i
                sed -i '1i\\\\\makeatletter\\\\\def\\\\\@captype{table}\\\\\makeatother\n\\\\\scriptsize\n\\\\\begin{center}\n\\\\\begin{longtable}{|p{3cm}|p{5cm}|p{5.4cm}|}\n\\\\\hline' $tmpPath/tmpfile$i
                sed -i '$a\\\\\hline\n\\\\\end{longtable}\n\\\\\end{center}\n' $tmpPath/tmpfile$i
                ;;


        esac
    fi
    while read line
    do
        echo $line >> $outputfile
    done < $tmpPath/tmpfile$i
done

#1 将文本文件转化成.tex 格式
#文本头部添加tex 头
sed -i '1i\\\documentclass[a4paper]{article}\n\\\usepackage[english]{babel}\n\\\usepackage[utf8x]{inputenc}\n\\\usepackage{amsmath}\n\\\usepackage{graphicx}\n\\\usepackage{longtable}\n\\\usepackage[colorinlistoftodos]{todonotes}\n\\\usepackage[UTF8]{ctex}\n\\\usepackage{fancyhdr}\n\\\pagestyle{fancy}\n\\\lhead{\\includegraphics[scale=0.3]{logo.jpg}}\n\\rhead{固件分析报告}\n\\\usepackage[textwidth=14.5cm]{geometry}\n\\\usepackage{blindtext}\n\\\parindent=0pt\n\\\usepackage[colorlinks=true,allcolors=blue]{hyperref}\n\\\setlength{\\headheight}{27pt}\n\\\begin{document}\n\\title{固件分析报告}\n\\\maketitle\n\\thispagestyle{fancy}\n\\\begin{sloppypar}' $outputfile


#文本尾部添加tex 尾
sed -i '$a\\\end{sloppypar}\n\\\end{document}' $outputfile

#文本格式转化成.tex
mv $outputfile ${outputfile}.tex

#处理特殊字符_,^,&,^@～\0,\"->",$HOME去除% ，(以后可能会出现&解析问题，若出现将indicators.py文件中的&先转成\&后再将\&转成&)
#sed -i 's#_#\\_#g ; s#\^#\\^#g ; s#&#\\&#g ; s/\x0//g ; s/\\"/"/g ; s/\$//g' ${outputfile}.tex
sed -i 's#_#\\_#g ; s#\^#\\^#g  ; s/\x0//g ; s/\\"/"/g ; s/\$//g' ${outputfile}.tex

echo "生成PDF"
xelatex ${outputfile}.tex >/dev/null 2>&1
xelatex ${outputfile}.tex >/dev/null 2>&1

rm -R $tmpPath
mv ${outputfile}.pdf _${outputfile}.pdf
mv _${outputfile}.pdf $EXTRACT_PATH
rm ${outputfile}*
#rm -rf $EXTRACT_PATH/_"${FIRM_NAME}".extracted
cd -

#给其他用户访问文件夹的权限
chmod o+r ${EXTRACT_PATH}/*
