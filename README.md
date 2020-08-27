# wso2-organization-userstore-manager
User store manager to cater organization management operations


```
curl -X GET \
  'https://localhost:9443/scim2/Users?startIndex=1&count=10&domain=WSO2.COM&filter=userName+sw+ki+and+urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization+Eq+26836e36-c078-4af1-baee-73cc5e1fae32&attributes=userName,name.familyName' \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
  -H 'Content-Type: application/json' \
  -H 'Postman-Token: b0befcd5-87cb-4205-aea9-0262e5275526' \
  -H 'cache-control: no-cache' \
```
