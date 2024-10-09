import smtplib

port = 465

password = "bgxt uqqx ipsw avws"
my_email = "adekomuheez567@gmail.com"



with smtplib.SMTP("smtp.gmail.com", 587) as connection:
    connection.starttls()
    connection.login(user=my_email, password=password)
    connection.sendmail(from_addr=my_email, to_addrs="mzscripterx5@gmail.com", msg=f"Subject:QuickDash| Help \n\n I'm having problems logging into my account")
    connection.close()

print("Email Sent")