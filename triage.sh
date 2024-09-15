#!/bin/bash

#source /tmp/workspace/env.txt
source param.txt

#デバッグ用
  #echo "param.txtの中身"
  #cat param.txt

# LeanSeeksのアップロード情報を取得し、URLとTokenを変数に入れる
echo "------- LeanSeeksのアップロードURLを情報取得中"
cred=$(curl -X "GET" "${ls_url_demo}/api/vulnerability-scan-results/upload-destination" -H "accept: application/json" -H "Accept-Language: ja" -H "Authorization: Bearer ${ls_token_demo}" -H "${ua}")
s3_url=$(echo "${cred}" | jq -r ".uploadDestination.url")
s3_jwt=$(echo "${cred}" | jq -r ".uploadDestination.key")

echo ${s3_url}

# データをLeanSeeksにアップロードする
echo "------- データをLeanSeeksにアップロード中"
  #echo "デバッグ : LeanSeeksのアップロードデータのCVEカウント"
  #cat vuln_data.json | jq | grep -c "CVE-"
  #ls -lah vuln_data.json

curl -X 'PUT' "${s3_url}" --data-binary @vuln_data.json

# トリアージ用のパラメーターをparams.csvからmapping.jqを用いて生成する
echo "------- トリアージリクエストパラメーターの準備中"
  #echo "デバッグ"
  #echo "App_Name: ${app_name}"
  #echo "App_Priority: ${app_priority}"
  #echo "Scanner: ${scanner}"

cat mapping.jq | sed -e "s/-SCANNER-/${scanner}/g" > mapping-rp.jq
param="{ \"application_name\": \"${app_name}\", \"importance\": \"${app_priority}\", \"is_template\": false, \"pods\":"
param+=$(jq -R -s -f mapping-rp.jq params.csv | jq -r -c '[.[] |select(.pod_name != null and .is_root != "is_root" )]'| sed -e 's/"¥r"//g')"}"
echo ${param} | sed 's/"TRUE"/true/g' | sed -e 's/"FALSE"/false/g' > "param.json"

  #echo "デバッグ"
  #echo "param.jsonの中身"
  #cat param.json | jq

# トリアージリクエストを実行する
echo "------- トリアージリクエスト実行中"
curl -X 'POST' "${ls_url_demo}/api/triage-requests" -H 'accept: application/json' -H 'Accept-Language: ja' -H "Vulnerability-Scan-Result-Resource-Id: ${s3_jwt}" -H "Authorization: Bearer ${ls_token_demo}" -H 'Content-Type: application/json' -H "${ua}" -d @param.json > result.json
triage_id=$(cat result.json | jq -r ".triage.triageId")
cat result.json | jq

# トリアージ結果を10秒間隔で取得する。成功するまで繰り返す。
i=1
while true
  do
              echo "---- 処理待ち_${i}"
              curl -X 'GET' "${ls_url_demo}/api/triage-results/${triage_id}/status" -H 'accept: application/json' -H 'Accept-Language: ja' -H "Authorization: Bearer ${ls_token_demo}" -H 'Content-Type: application/json' -H "$ua" -o t_result.json
              status=$(cat t_result.json | jq -r ".triage.status")
              echo "statusは「${status}」です"
              if [ "${status}" == "成功" ]; then
                cat t_result.json | jq -r ".triage"
                if [ $(cat t_result.json | jq -r ".triage.level5VulnerabilityCounts") != 0 ]; then
                  echo "緊急対処が必要な脆弱性が見つかりました！"
                  echo "レベル5 緊急対処: "$(cat t_result.json | jq -r ".triage.level5VulnerabilityCounts")"件"
                  exit 1
                elif [ $(cat t_result.json | jq -r ".triage.level4VulnerabilityCounts") != 0 ]; then
                  echo "緊急対処が推奨される脆弱性が見つかりました！"
                  echo "レベル4 緊急対処推奨: "$(cat t_result.json | jq -r ".triage.level4VulnerabilityCounts")"件"
                  exit 1
                elif [ $(cat t_result.json | jq -r ".triage.level3VulnerabilityCounts") != 0 ]; then
                  echo "対処計画が必要な脆弱性が見つかりましたが、緊急性が低いためパイプラインを継続します"
                  echo "レベル3 対処計画: "$(cat t_result.json | jq -r ".triage.level3VulnerabilityCounts")"件"
                  rm -rf work
                  rm -f vuln_data.json
                  exit 0
                elif [ $(cat t_result.json | jq -r ".triage.level2VulnerabilityCounts") != 0 ]; then
                  echo "対処計画が推奨される脆弱性が見つかりましたが、緊急性が低いためパイプラインを継続します"
                  echo "レベル2 対処計画推奨: "$(cat t_result.json | jq -r ".triage.level2VulnerabilityCounts")"件"
                  rm -rf work
                  rm -f vuln_data.json
                  exit 0
                else
                  echo "緊急性のある脆弱性が検知されなかったため、パイプラインを継続します"
                  rm -rf work
                  rm -f vuln_data.json
                  exit 0
                fi
              elif [ "${status}" == null ]; then
                echo "トリアージリクエストが失敗しました。"
                cat t_result.json | jq
                exit 1
              fi
              sleep 10
              i=$((i+1))
  done
