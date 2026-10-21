# Demo file for VS007. Eight vulnerable lines, then safe ones.
# This file is only scanned, never run, so yaml/numpy/pandas don't need to be installed.
import json
import pickle
import marshal
import shelve

import numpy as np # type: ignore
import pandas as pd # type: ignore
import yaml # type: ignore

# Stand in values so editors don't complain about undefined names
f = open("data.pkl", "rb")
data = b"..."
text = "a: 1"

# vulnerable  
pickle.load(f) # pickle
pickle.loads(data) # pickle
marshal.loads(data) # marshal
shelve.open("cache") # shelve uses pickle inside
yaml.load(text) # no Loader
yaml.load(text, Loader=yaml.Loader) # unsafe Loader
np.load("a.npy", allow_pickle=True) # numpy with pickle on
pd.read_pickle("df.pkl") # alias: pd -> pandas

# --- safe ---
yaml.safe_load(text)
yaml.load(text, Loader=yaml.SafeLoader)
json.loads('{"a": 1}')
np.load("a.npy") # allow_pickle defaults to off
pickle.dumps({"a": 1}) # dumping is fine, loading is the risk