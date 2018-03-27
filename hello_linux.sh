#!/bin/bash
echo 'Hello Linux'
while read line
do
  echo $line
done >output.txt
