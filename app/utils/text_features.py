# app/utils/text_features.py
from scipy.sparse import hstack, csr_matrix


def extraer_features_texto(text: str, vectorizer, scaler):
    X_tfidf = vectorizer.transform([text])
    length_scaled = scaler.transform([[len(text)]])
    from scipy.sparse import csr_matrix, hstack
    X_final = hstack([X_tfidf, csr_matrix(length_scaled)])


    return X_final