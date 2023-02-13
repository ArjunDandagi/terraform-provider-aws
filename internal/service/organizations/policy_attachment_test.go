package organizations_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tforganizations "github.com/hashicorp/terraform-provider-aws/internal/service/organizations"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
)

func testAccPolicyAttachment_Account(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_policy_attachment.test"
	policyIdResourceName := "aws_organizations_policy.test"
	targetIdResourceName := "aws_organizations_organization.test"

	serviceControlPolicyContent := `{"Version": "2012-10-17", "Statement": { "Effect": "Allow", "Action": "*", "Resource": "*"}}`
	tagPolicyContent := `{ "tags": { "Product": { "tag_key": { "@@assign": "Product" }, "enforced_for": { "@@assign": [ "ec2:instance" ] } } } }`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t); acctest.PreCheckOrganizationsAccount(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, organizations.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckPolicyAttachmentDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachmentConfig_account(rName, organizations.PolicyTypeServiceControlPolicy, serviceControlPolicyContent),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyAttachmentExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "policy_id", policyIdResourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "target_id", targetIdResourceName, "master_account_id"),
				),
			},
			{
				Config: testAccPolicyAttachmentConfig_account(rName, organizations.PolicyTypeTagPolicy, tagPolicyContent),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyAttachmentExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "policy_id", policyIdResourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "target_id", targetIdResourceName, "master_account_id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccPolicyAttachment_OrganizationalUnit(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_policy_attachment.test"
	policyIdResourceName := "aws_organizations_policy.test"
	targetIdResourceName := "aws_organizations_organizational_unit.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t); acctest.PreCheckOrganizationsAccount(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, organizations.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckPolicyAttachmentDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachmentConfig_organizationalUnit(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyAttachmentExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "policy_id", policyIdResourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "target_id", targetIdResourceName, "id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccPolicyAttachment_Root(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_policy_attachment.test"
	policyIdResourceName := "aws_organizations_policy.test"
	targetIdResourceName := "aws_organizations_organization.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t); acctest.PreCheckOrganizationsAccount(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, organizations.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckPolicyAttachmentDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachmentConfig_root(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyAttachmentExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "policy_id", policyIdResourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "target_id", targetIdResourceName, "roots.0.id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccPolicyAttachment_Account_ignoreLastPolicyException(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_policy_attachment.test"
	policyIdResourceName := "aws_organizations_policy.test"
	targetIdResourceName := "aws_organizations_organization.test"

	serviceControlPolicyContent := `{"Version": "2012-10-17", "Statement": { "Effect": "Allow", "Action": "*", "Resource": "*"}}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t); acctest.PreCheckOrganizationsAccount(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, organizations.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckPolicyAttachmentDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachmentConfig_account_ignoreLastPolicyException(rName, organizations.PolicyTypeServiceControlPolicy, serviceControlPolicyContent),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyAttachmentExists(ctx, resourceName),
					// remove all other SCPs in order to generate a contraint violation on destroy which
					// should be handled gracefully
					testAccRemoveAllOrganizationMasterAccountSCPsExcept(ctx, rName),
					resource.TestCheckResourceAttrPair(resourceName, "policy_id", policyIdResourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "target_id", targetIdResourceName, "master_account_id"),
				),
			},
		},
	})
}

func testAccPolicyAttachment_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_policy_attachment.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t); acctest.PreCheckOrganizationsAccount(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, organizations.EndpointsID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckPolicyAttachmentDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachmentConfig_organizationalUnit(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyAttachmentExists(ctx, resourceName),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tforganizations.ResourcePolicyAttachment(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// testAccRemoveAllOrganizationMasterAccountSCPsExcept removes all SCP's associated with the organization
// master account except for the provided policy name.
//
// This allows the ignore_last_policy_exception attribute to be exercised during destroy
func testAccRemoveAllOrganizationMasterAccountSCPsExcept(ctx context.Context, rName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).OrganizationsConn()
		out, err := conn.DescribeOrganizationWithContext(ctx, &organizations.DescribeOrganizationInput{})
		if err != nil {
			return fmt.Errorf("describe organization: %s", err)
		}
		if out == nil || out.Organization == nil {
			return fmt.Errorf("describe organization: empty output")
		}

		accountID := out.Organization.MasterAccountId
		scps, err := conn.ListPoliciesForTargetWithContext(ctx, &organizations.ListPoliciesForTargetInput{
			Filter:   aws.String(organizations.PolicyTypeServiceControlPolicy),
			TargetId: accountID,
		})
		if err != nil {
			return fmt.Errorf("list policies for target: %s", err)
		}

		for _, p := range scps.Policies {
			if aws.StringValue(p.Name) != rName {
				_, err := conn.DetachPolicyWithContext(ctx, &organizations.DetachPolicyInput{
					TargetId: accountID,
					PolicyId: p.Id,
				})
				if err != nil {
					return fmt.Errorf("detach policy: %s", err)
				}
			}
		}

		return nil
	}
}

func testAccCheckPolicyAttachmentDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).OrganizationsConn()

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_organizations_policy_attachment" {
				continue
			}

			targetID, policyID, err := tforganizations.DecodePolicyAttachmentID(rs.Primary.ID)

			if err != nil {
				return err
			}

			_, err = tforganizations.FindPolicyAttachmentByTwoPartKey(ctx, conn, targetID, policyID)

			if tfresource.NotFound(err) {
				continue
			}

			if tfawserr.ErrCodeEquals(err, organizations.ErrCodeAWSOrganizationsNotInUseException) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("Organizations Policy Attachment %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckPolicyAttachmentExists(ctx context.Context, n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Organizations Policy Attachment ID is set")
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).OrganizationsConn()

		targetID, policyID, err := tforganizations.DecodePolicyAttachmentID(rs.Primary.ID)

		if err != nil {
			return err
		}

		_, err = tforganizations.FindPolicyAttachmentByTwoPartKey(ctx, conn, targetID, policyID)

		return err
	}
}

func testAccPolicyAttachmentConfig_account(rName, policyType, policyContent string) string {
	return fmt.Sprintf(`
resource "aws_organizations_organization" "test" {
  enabled_policy_types = ["SERVICE_CONTROL_POLICY", "TAG_POLICY"]
}

resource "aws_organizations_policy" "test" {
  depends_on = [aws_organizations_organization.test]

  name    = "%s"
  type    = "%s"
  content = %s
}

resource "aws_organizations_policy_attachment" "test" {
  policy_id = aws_organizations_policy.test.id
  target_id = aws_organizations_organization.test.master_account_id
}
`, rName, policyType, strconv.Quote(policyContent))
}

func testAccPolicyAttachmentConfig_organizationalUnit(rName string) string {
	return fmt.Sprintf(`
resource "aws_organizations_organization" "test" {
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}

resource "aws_organizations_organizational_unit" "test" {
  name      = %[1]q
  parent_id = aws_organizations_organization.test.roots[0].id
}

resource "aws_organizations_policy" "test" {
  depends_on = [aws_organizations_organization.test]

  content = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }
}
EOF

  name = %[1]q
}

resource "aws_organizations_policy_attachment" "test" {
  policy_id = aws_organizations_policy.test.id
  target_id = aws_organizations_organizational_unit.test.id
}
`, rName)
}

func testAccPolicyAttachmentConfig_root(rName string) string {
	return fmt.Sprintf(`
resource "aws_organizations_organization" "test" {
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}

resource "aws_organizations_policy" "test" {
  depends_on = [aws_organizations_organization.test]

  content = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }
}
EOF

  name = %[1]q
}

resource "aws_organizations_policy_attachment" "test" {
  policy_id = aws_organizations_policy.test.id
  target_id = aws_organizations_organization.test.roots[0].id
}
`, rName)
}

func testAccPolicyAttachmentConfig_account_ignoreLastPolicyException(rName, policyType, policyContent string) string {
	return fmt.Sprintf(`
resource "aws_organizations_organization" "test" {
  enabled_policy_types = ["SERVICE_CONTROL_POLICY", "TAG_POLICY"]
}

resource "aws_organizations_policy" "test" {
  depends_on = [aws_organizations_organization.test]

  name    = "%s"
  type    = "%s"
  content = %s
}

resource "aws_organizations_policy_attachment" "test" {
  policy_id = aws_organizations_policy.test.id
  target_id = aws_organizations_organization.test.master_account_id

  ignore_last_policy_exception = true
}
`, rName, policyType, strconv.Quote(policyContent))
}
