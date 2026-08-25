import requests

response = requests.get(https://www.example.com”)
if response.status_code == 200:
	print(‘Successfully reached example.com”)
else:
	print(“Request failed with status:”, response.status_code)
