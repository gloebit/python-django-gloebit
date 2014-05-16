from django.conf.urls import patterns, url

from gloebitexample import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^purchase/item/$', views.purchase_item, name='purchase_item'),
    url(r'^gloebit_callback/$', views.gloebit_callback,
        name='gloebit_callback'),
    url(r'^logout/$', views.logout, name='logout'),
)
