from flask import render_template, session

def home_details():
    return render_template('front/index.html')


def page_not_found_template():
    return render_template('front/404.html'), 404