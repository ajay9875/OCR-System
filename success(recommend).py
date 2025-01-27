
# Load course dataset and fill missing values
courses = pd.read_csv("courses.csv").fillna('').astype(str)

# Ensure necessary columns are present
if "title" not in courses.columns or "Description" not in courses.columns:
    raise ValueError("Dataset must contain 'title' and 'description' columns.")

# TF-IDF Vectorizer to process course descriptions
tfidf = TfidfVectorizer(stop_words="english")
tfidf_matrix = tfidf.fit_transform(courses["Description"])

if not(tfidf or tfidf_matrix):
    raise ValueError("tfidf and tfidf_matrix have not been created!")

# Compute cosine similarity matrix
cosine_sim = cosine_similarity(tfidf_matrix, tfidf_matrix)
if not cosine_sim.any():
    raise ValueError("cosine_sim has not been generated!")

def recommend_courses(course_title, num_recommendations=5):
    """ Returns top similar courses based on content similarity """
        
    # Get the index of the input course title
    idx_list = courses.index[courses["title"] == course_title]
    if len(idx_list) == 0:
        return ["Course not found!"]
    
    idx = idx_list[0]  # Choose the first match (if multiple courses have the same title)
    
    # Get the cosine similarity scores for the input course
    scores = list(enumerate(cosine_sim[idx]))
    
    # Sort the scores based on similarity in descending order
    sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)[1:num_recommendations+1]
    
    # Extract the course titles of the most similar courses
    recommended_courses = [courses.iloc[i[0]]["title"] for i in sorted_scores]
    
    return recommended_courses



@app.route('/', methods=['GET', 'POST'])
def home():
    """ Home page with user login check and course recommendation """
    # Redirect to login if user is not logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Sidebar links for the index template
    sidebar_links = {
        "about": url_for("about"),
        "services": url_for("services"),
        "contact": url_for("contact")
    }
    
    # Fetch username from session
    username = session.get("username")

    # Initialize recommendations to None
    recommendations = None
    if request.method == "POST":
        selected_course = request.form.get('course')
        if selected_course:
            recommendations = recommend_courses(selected_course) 
        else:
            recommendations = ['Please enter a valid course name.']
        

    # Render the page with necessary context
    response = make_response(render_template(
        "index.html", 
        username=username, 
        sidebar_links=sidebar_links,
        courses=courses["title"].tolist(),
        recommendations=recommendations,
    ))

    # Prevent caching of the home page
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


#Title description showing successfully
def recommend_courses(course_title, num_recommendations=5,similarity_cutoff=1, fuzzy_cutoff=75):
    """ Returns similar courses using fuzzy matching & content similarity based on all fields """
    
    course_title = course_title.lower()
    match = process.extractOne(course_title, courses["title"].tolist(), score_cutoff=fuzzy_cutoff)
    
    if match is None:
        return []  # No match found

    best_match = match[0]  # Best matching title
    idx_list = courses.index[courses["title"] == best_match]
    
    if idx_list.empty:
        return []  # If no matching course is found

    idx = idx_list[0]
    scores = list(enumerate(cosine_sim[idx]))
    
    # Apply similarity cutoff
    filtered_scores = [course for course in scores if course[1] > similarity_cutoff]

    # Sort by similarity, excluding itself
    sorted_scores = sorted(filtered_scores, key=lambda x: x[1])[1:num_recommendations+1]

    # Include all course details in the recommendations
    recommended_courses = [
        {
            "title": courses.iloc[i[0]]["title"],
            "description": courses.iloc[i[0]]["Description"],
            "difficulty_level": courses.iloc[i[0]]["Difficulty_Level"],
            "duration_weeks": courses.iloc[i[0]]["Duration(weeks)"],
        }
        for i in sorted_scores
    ]
    
    return recommended_courses
