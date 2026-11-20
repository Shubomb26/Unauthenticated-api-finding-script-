# 1. Create your endpoint list (full URLs, one per line)
cat > endpoints.txt << 'EOF'

...
EOF
 
# 2. Run it
python3 api_scan.py endpoints.txt
 
# Options
python3 api_scan.py endpoints.txt -o my_results.xlsx -w 16 -t 25
python3 api_scan.py endpoints.txt --rescan       # force fresh scan (ignore cache)
python3 api_scan.py endpoints.txt --from-cache   # re-render sheet, no network
