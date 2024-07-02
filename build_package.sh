rm -rf dist
python -m build
read -s -p "Entery PyPi Token: " TOKEN
python -m twine upload dist/* -u__token__ -p$TOKEN
