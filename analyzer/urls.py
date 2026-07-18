from django.urls import path

from analyzer import views


app_name = "analyzer"

urlpatterns = [
    path("", views.analyze_incident, name="analyze"),
]