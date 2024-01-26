# level: WARNING
# start_line: 14
# end_line: 14
# start_column: 10
# end_column: 22
import pickle


def load_pickle_file(file_path):
    with open(file_path, "rb") as file:
        data = file.read()

    # WARNING: Unpickle data without proper validation
    obj = pickle.loads(data)
    return obj


# Example usage (assuming 'malicious.pickle' contains malicious code)
pickle_file = "malicious.pickle"
loaded_object = load_pickle_file(pickle_file)
