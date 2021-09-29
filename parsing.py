import csv
import json
import sys

def read_results(csv_file_path):
	out = {
		"templateID":"http2smugl",
		"info":{
			"reference":"",
			"name":"Http/2 Request Smuggling",
			"author":"none",
			"severity":"medium",
			"description":""
			},
		"type":"http",
		"host":"target",
		"matched":"",
		"ip":"",
		"timestamp":""
		}

	with open(csv_file_path) as csv_file:
		csv_reader = csv.DictReader(csv_file)
		for rows in csv_reader:
			if rows["result"] != "indistinguishable":
				out["host"] = rows["target"]
				out["matched"] = rows["target"]
				out["info"]["description"] = rows["result"]
				print(json.dumps(out))

def main():
	csv_result = sys.argv[1]
	read_results(csv_result)
	
if __name__ == '__main__':
	main()
