import pandas as pd
import json

def parse_csv_log(filepath):
    df = pd.read_csv(filepath)
    return df

def parse_json_log(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    return pd.DataFrame(data)