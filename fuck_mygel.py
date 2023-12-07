import requests
import json
import os
import hashlib

BASE_URL = "https://cpes.legym.cn"

LOGIN_URL = f"{BASE_URL}/authorization/user/manage/login"
GET_ACTIVITY_URL = f"{BASE_URL}/education/app/activity/getActivityList"
SIGNUP_ACTIVITY_URL = f"{BASE_URL}/education/app/activity/signUp"
SIGNIN_ACTIVITY_URL = f"{BASE_URL}/education/activity/app/attainability/sign"
HEADERS = {"Content-Type": "application/json"}

USERNAME = os.environ["USERNAME"]
PASSWORD = os.environ["PASSWORD"]
KEYWORD = os.environ["KEYWORD"]
SALT = os.environ["SALT"]


class User:
    def __init__(self, username: str, password: str, keyword: str, headers: dict):
        self.username = username
        self.password = password
        self.keyword = keyword
        self.id = ""
        self.headers = headers
        self.activity_id = ""

    def get_signDigital(self):
        data: str = self.activity_id + "1" + self.id + SALT
        return hashlib.sha1(data.encode()).hexdigest()

    def request(self, method: str, url: str, headers: dict, data: str, error_text=""):
        res = requests.request(method=method, url=url, headers=headers, data=data)
        if res.status_code != 200:
            print(res.reason, res.text)
            raise Exception(error_text)
        return json.loads(res.text)

    def login(self):
        payload = json.dumps(
            {"userName": self.username, "password": self.password, "entrance": 1}
        )
        res = self.request(
            method="POST",
            url=LOGIN_URL,
            headers=self.headers,
            data=payload,
            error_text="登录失败",
        )
        access_token = res["data"]["accessToken"]
        self.headers["Authorization"] = "Bearer " + access_token
        self.id = res["data"]["id"]
        self.activity_id = self.get_activity_id()

    def get_activity_id(self):
        payload = json.dumps(
            {
                "name": "",
                "campus": "",
                "page": 1,
                "size": 999,
                "state": "",
                "topicId": "",
                "week": "",
            }
        )
        res = self.request(
            method="POST",
            url=GET_ACTIVITY_URL,
            headers=self.headers,
            data=payload,
            error_text="获取活动列表失败",
        )
        activities = res["data"]["items"]
        for activity in activities:
            if self.keyword in activity["name"] and activity["stateName"] == "活动进行中":
                return activity["id"]
        raise Exception("未找到该活动")

    def signup_activity(self):
        payload = json.dumps({"activityId": self.activity_id})
        self.request(
            method="POST",
            url=SIGNUP_ACTIVITY_URL,
            headers=self.headers,
            data=payload,
            error_text="活动报名失败",
        )

    def signin_activity(self):
        signDigital = self.get_signDigital()
        payload = json.dumps(
            {
                "activityId": self.activity_id,
                "times": 2,
                "pageType": "activity",
                "userId": self.id,
                "activityType": 0,
                "attainabilityType": 1,
                "signDigital": signDigital,
            }
        )
        self.request(
            method="PUT",
            url=SIGNIN_ACTIVITY_URL,
            headers=self.headers,
            data=payload,
            error_text="活动签到失败",
        )


if __name__ == "__main__":
    user = User(USERNAME, PASSWORD, KEYWORD, HEADERS)
    user.login()
    user.signup_activity()
    user.signin_activity()
