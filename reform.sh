#!/bin/bash

## file check
if [ $# -lt 1 ]; then
  echo "ファイル名を指定してください"
  exit 1
fi

## 変数指定
filename=${1}
dirname=$(echo ${1} | cut -d . -f 1)
it=1

## CVEの一覧を作る
mkdir ${dirname}
cat ${filename} | jq -r -c '.firmware.observationsFull[] |[ .affectedComponents[].softwareComponents[].product, .affectedComponents[].softwareComponents[].version, .observationDefinition.cves.edges[].node.cveId, .observationDefinition.cves.edges[].node.severity, .observationDefinition.cves.edges[].node.baseSeverityV3, .observationDefinition.cves.edges[].node.cvssMetricV3, .observationDefinition.cves.edges[].node.baseSeverityV2, .observationDefinition.cves.edges[].node.cvssMetricV2, .exploits[].downloadUrl ]'  > ${dirname}/cve_list.txt
## CVE数をカウント
number=$(cat ${dirname}/cve_list.txt | grep -c "CVE-")

## データを一行ずつ読みながらJSONを生成する
vuln_data='['
while read row; do

packageName=$(echo ${row} | cut -f 1 -d ,| sed -e 's/\[//g' | sed -e 's/"//g')
packageVersion=$(echo ${row} | cut -f 2 -d ,| sed -e 's/"//g')
cveId=$(echo ${row} | cut -f 3 -d ,| sed -e 's/"//g')
cvssScore=$(echo ${row} | cut -f 4 -d ,| sed -e 's/"//g')
if [ $(echo ${row} | cut -f 5 -d ,) == null ]; then
  #CVSS V3のメトリックがない場合
  severity_o=$(echo ${row} | cut -f 7 -d ,| sed -e 's/"//g')
  AV_o=$(echo ${row} | cut -f 10 -d ,| cut -f 2 -d :)
  I_o=$(echo ${row} | cut -f 13 -d ,| cut -f 2 -d :)
  AC_o=$(echo ${row} | cut -f 14 -d ,| cut -f 2 -d :)
  A_o=$(echo ${row} | cut -f 15 -d ,| cut -f 2 -d :)
  C_o=$(echo ${row} | cut -f 16 -d ,| cut -f 2 -d :)
else
  #CVSS V3のメトリックがある場合
  severity_o=$(echo ${row} | cut -f 5 -d ,| sed -e 's/"//g')
  AV_o=$(echo ${row} | cut -f 9 -d ,| cut -f 2 -d :)
  I_o=$(echo ${row} | cut -f 12 -d ,| cut -f 2 -d :)
  AC_o=$(echo ${row} | cut -f 14 -d ,| cut -f 2 -d :)
  A_o=$(echo ${row} | cut -f 15 -d ,| cut -f 2 -d :)
  C_o=$(echo ${row} | cut -f 17 -d ,| cut -f 2 -d :)
fi

#severityの小文字変換
severity=$(echo ${severity_o} | tr '[:upper:]' '[:lower:]')
# AVの値変換
if [ ${AV_o} == "\"NETWORK\"" ]; then AV="N"
elif [ ${AV_o} == "\"ADJACENT_NETWORK\"" ]; then AV="A"
elif [ ${AV_o} == "\"LOCAL\"" ]; then AV="L"
else AV="P"
fi
# ACの値変換
if [ ${AC_o} == "\"LOW\"" ]; then AC="L"
else AC="H"
fi
# Cの値変換
if [ ${C_o} == "\"NONE\"}" ]; then C="N"
elif [ ${C_o} == "\"LOW\"}" ] || [ ${C_o} == "\"PARTIAL\"}" ] ; then C="L"
else C="H"
fi
# Iの値変換
if [ ${I_o} == "\"NONE\"" ]; then I="N"
elif [ ${I_o} == "\"LOW\"" ] || [ ${I_o} == "\"PARTIAL\"" ] ; then I="L"
else I="H"
fi
# Aの値変換
if [ ${A_o} == "\"NONE\"" ]; then A="N"
elif [ ${A_o} == "\"LOW\"" ] || [ ${A_o} == "\"PARTIAL\"" ] ; then A="L"
else A="H"
fi

## JSONに各変数を代入する
vuln_data+='{
    "cveId": "'${cveId}'",
    "packageName": "'${packageName}'",
    "packageVersion": "'${packageVersion}'",
    "severity": "'${severity}'",
    "cvssScore": "'${cvssScore}'",
    "title": "",
    "description": "",
    "link": "",
    "AV": "'"${AV}"'",
    "AC": "'"${AC}"'",
    "C": "'"${C}"'",
    "I": "'"${I}"'",
    "A": "'"${A}"'",
    "hasFix": "",
    "exploit": "",
    "publicExploits": "",
    "published": "",
    "updated": "",
    "type": ""'
  if [ ${it} -eq ${number} ]; then
    vuln_data+="}]"
    echo ${vuln_data} | jq > "${dirname}_LS.json"
  else
    vuln_data+="},"
 fi
  echo "${it}/${number}"
  it=$((it+1))

done < ${dirname}/cve_list.txt