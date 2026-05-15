# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 10
# end_column: 21
import pickle


def load_pickle_file(file_path):
    # WARNING: Unpickle data without proper validation
obj = # FIX: 替换pickle为安全格式
file_path)
    return obj


# Example usage (assuming 'malicious.pickle' contains malicious code)
pickle_file = "malicious.pickle"
loaded_object = load_pickle_file(pickle_file)
