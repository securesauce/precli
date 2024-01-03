# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 0
# end_column: 14
import pickle

import pandas as pd


df = pd.DataFrame({"col_A": [1, 2]})
pick = pickle.dumps(df)
pd.read_pickle(pick)
