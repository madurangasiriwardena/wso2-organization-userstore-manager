# wso2-organization-userstore-manager
User store manager to cater organization management operations (wso2is-5.10.0)

##Custom user store manager configurations
1. Make default `organization` SCIM2 attribute a complex attribute with `organization.id` and `organization.name` sub-attributes 
by adding/changing below in the `<IS_HOME>>/repository/conf/scim2-schema-extension.config` file.
```
{
"attributeURI":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization.id",
"attributeName":"id",
"dataType":"string",
"multiValued":"false",
"description":"The id of the organization",
"required":"false",
"caseExact":"false",
"mutability":"readwrite",
"returned":"default",
"uniqueness":"none",
"subAttributes":"null",
"canonicalValues":[],
"referenceTypes":[]
},
{
"attributeURI":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization.name",
"attributeName":"name",
"dataType":"string",
"multiValued":"false",
"description":"The name of the organization",
"required":"false",
"caseExact":"false",
"mutability":"readwrite",
"returned":"default",
"uniqueness":"none",
"subAttributes":"null",
"canonicalValues":[],
"referenceTypes":[]
},
{
"attributeURI":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization",
"attributeName":"organization",
"dataType":"complex",
"multiValued":"false",
"description":"Identifies an organization",
"required":"false",
"caseExact":"false",
"mutability":"readWrite",
"returned":"default",
"uniqueness":"none",
"subAttributes":"id name",
"canonicalValues":[],
"referenceTypes":[]
}, 
```
2. From the Management Console, create new External claims(`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` dialect) and local claims(`http://wso2.org/claims` dialect) and map them.
(Map LDAP attributes to the newly defined local claims)
```
Example local claims:
    http://wso2.org/claims/organizationName
    http://wso2.org/claims/organizationId
Example external claims:
    urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization.name
    urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization.id
```
3. Make sure that you have the `<IS_HOME>/repository/resources/conf/templates/repository/conf/identity/identity.xml.j2` updated with the new configurations for the organization management feature.
```
    <!--Organization management properties-->
    <OrganizationMgt>
            <OrgNameClaimUri>{{organization.mgt.org_name_claim_uri}}</OrgNameClaimUri>
            <OrgIdClaimUri>{{organization.mgt.org_id_claim_uri}}</OrgIdClaimUri>
            <AttributeValidatorClass>{{organization.mgt.attribute_validator_class}}</AttributeValidatorClass>
    </OrganizationMgt>
```
4. Define organization mgt related claim URIs in the `<IS_HOME>>/repository/conf/deployment.toml`
```
[organization.mgt]
org_name_claim_uri = "http://wso2.org/claims/organizationName"
org_id_claim_uri = "http://wso2.org/claims/organizationId"
attribute_validator_class = "org.wso2.carbon.identity.organization.mgt.core.validator.AttributeValidatorImpl"
```
5. Build the project and add the artifact in the `<IS_HOME>/repository/components/dropins` directory
6. Restart the server

##Sample SCIM2 requests 
List/filter users of an organization (define organization by its 'id' or 'name')
```
curl -X GET \
  'https://localhost:9443/scim2/Users?startIndex=0&count=10&domain=WSO2.COM&filter=urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization.id+Eq+cca6bb80-6252-4d98-9331-c8c6d48dbca3' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Postman-Token: c8e48be0-e71d-45cd-b222-e258711d1a2d' \
  -H 'cache-control: no-cache'

curl -X GET \
  'https://localhost:9443/scim2/Users?startIndex=0&count=10&domain=WSO2.COM&filter=urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization.name+Eq+Hesei' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Postman-Token: c8e48be0-e71d-45cd-b222-e258711d1a2d' \
  -H 'cache-control: no-cache'
```

Add user to an organization (define organization by its 'id' or 'name')
```
curl -X POST \
  https://localhost:9443/scim2/Users \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
  -H 'Content-Type: application/json' \
  -H 'Postman-Token: 1410cbfb-1b40-4690-afc0-cbddecd00a24' \
  -H 'cache-control: no-cache' \
  -d '{
    "schemas": [],
    "name": {
        "givenName": "John34",
        "familyName": "Doe"
    },
    "userName": "WSO2.com/johndoe34",
    "password": "abc123",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        "organization": {
            "id": "Hesei3"
        }
    }
}'

curl -X POST \
  https://localhost:9443/scim2/Users \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
  -H 'Content-Type: application/json' \
  -H 'Postman-Token: 1410cbfb-1b40-4690-afc0-cbddecd00a24' \
  -H 'cache-control: no-cache' \
  -d '{
    "schemas": [],
    "name": {
        "givenName": "John34",
        "familyName": "Doe"
    },
    "userName": "WSO2.com/johndoe34",
    "password": "abc123",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
        "organization": {
            "name": "Hesei3"
        }
    }
}'
```
