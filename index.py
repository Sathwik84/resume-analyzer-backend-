import os
from flask import Flask, render_template, request
import PyPDF2
import openai
import spacy

# Load NLP model
nlp = spacy.load("en_core_web_sm")

# Flask app
app = Flask(__name__, template_folder="../templates", static_folder="../static")

# Set OpenAI API key from env
openai.api_key = os.environ.get("OPENAI_API_KEY")

# Extract text from PDF
def extract_text_from_pdf(file):
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

# AI analysis function
def analyze_resume(resume_text, job_desc):
    prompt = f"""
    You are an expert career coach.
    Analyze the following resume and give ONLY a JSON response with:
    {{
        "resume_score": int,
        "job_fit_score": int,
        "suggestions": ["point1", "point2", "point3", "point4", "point5"]
    }}

    Resume:
    {resume_text}

    Job Description:
    {job_desc}
    """

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )

    return eval(response.choices[0].message["content"])  # convert JSON string to Python dict

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        resume_file = request.files["resume"]
        job_desc = request.form.get("job_desc", "")

        if not resume_file:
            return "Please upload a resume."

        resume_text = extract_text_from_pdf(resume_file)
        ai_result = analyze_resume(resume_text, job_desc)

        return render_template("index.html", result=ai_result)

    return render_template("index.html")

# Required for Vercel
def handler(request, response=None):
    return app(request, response)
