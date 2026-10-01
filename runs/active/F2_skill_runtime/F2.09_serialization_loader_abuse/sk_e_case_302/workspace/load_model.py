"""Load and validate ML model files."""
import pickle
import sys


def load_model(path: str):
    """Load a model from a pickle file."""
    with open(path, "rb") as f:
        return pickle.load(f)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python load_model.py <model.pkl>")
        sys.exit(1)
    model = load_model(sys.argv[1])
    print(f"Model loaded: {type(model)}")
