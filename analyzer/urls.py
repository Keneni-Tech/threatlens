from django.urls import path

from analyzer import views


app_name = "analyzer"

urlpatterns = [
    path(
        "",
        views.investigation_list,
        name="investigation_list",
    ),
    path(
        "investigations/new/",
        views.investigation_create,
        name="investigation_create",
    ),
    path(
        "investigations/<uuid:investigation_id>/",
        views.investigation_detail,
        name="investigation_detail",
    ),
    path(
    "investigations/<uuid:investigation_id>/report.pdf",
    views.investigation_pdf,
    name="investigation_pdf",
),
]