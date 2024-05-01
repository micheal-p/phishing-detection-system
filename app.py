#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)

def load_model():
    # Load CSV data
    data = pd.read_csv("phishing.csv")

    # Split the data into features (X) and target labels (y)
    X = data.drop(columns=["class"])
    y = data["class"]

    # Define and train model
    gbc = GradientBoostingClassifier()  # Create a new instance of GradientBoostingClassifier
    gbc.fit(X, y)  # Fit the model to the data
    return gbc

gbc = load_model()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,31)  # Ensure the input shape is (1, 31)

        y_pred = gbc.predict(x)[0]
        # 1 is safe       
        # -1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        pred = "It is {0:.2f}% safe to go".format(y_pro_phishing*100)
        return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=url, pred=pred)
    return render_template("index.html", xx=-1)


if __name__ == "__main__":
    app.run(debug=True)
