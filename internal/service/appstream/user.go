package appstream

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/appstream"
	"github.com/hashicorp/aws-sdk-go-base/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func ResourceUser() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceUserCreate,
		ReadWithoutTimeout:   resourceUserRead,
		UpdateWithoutTimeout: resourceUserUpdate,
		DeleteWithoutTimeout: resourceUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"authentication_type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice(appstream.AuthenticationType_Values(), false),
			},
			"created_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"first_name": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(0, 2048),
			},
			"last_name": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(0, 2048),
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"user_name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(1, 128),
			},
		},
	}
}

func resourceUserCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).AppStreamConn

	userName := d.Get("user_name").(string)
	authType := d.Get("authentication_type").(string)

	input := &appstream.CreateUserInput{
		AuthenticationType: aws.String(authType),
		UserName:           aws.String(userName),
	}

	if v, ok := d.GetOk("first_name"); ok {
		input.FirstName = aws.String(v.(string))
	}

	if v, ok := d.GetOk("last_name"); ok {
		input.LastName = aws.String(v.(string))
	}

	if v, ok := d.GetOk("message_action"); ok {
		input.MessageAction = aws.String(v.(string))
	}

	_, err := conn.CreateUserWithContext(ctx, input)

	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating AppStream User (%s): %w", d.Id(), err))
	}

	if _, err = waitUserAvailable(ctx, conn, userName, authType); err != nil {
		return diag.FromErr(fmt.Errorf("error waiting for AppStream User (%s) to be available: %w", d.Id(), err))
	}

	// Enabling/disabling workflow
	if v, ok := d.GetOk("enabled"); ok {
		if v.(bool) {
			input := &appstream.EnableUserInput{
				AuthenticationType: aws.String(authType),
				UserName:           aws.String(userName),
			}

			_, err = conn.EnableUserWithContext(ctx, input)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error enabling AppStream User (%s): %w", d.Id(), err))
			}
		} else {
			input := &appstream.DisableUserInput{
				AuthenticationType: aws.String(authType),
				UserName:           aws.String(userName),
			}

			_, err = conn.DisableUserWithContext(ctx, input)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error disabling AppStream User (%s): %w", d.Id(), err))
			}
		}
	}

	d.SetId(EncodeUserID(userName, authType))

	return resourceUserRead(ctx, d, meta)
}

func resourceUserRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).AppStreamConn

	userName, authType, err := DecodeUserID(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error decoding id AppStream User (%s): %w", d.Id(), err))
	}

	user, err := FindUserByUserNameAndAuthType(ctx, conn, userName, authType)

	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading Appstream User (%s): %w", d.Id(), err))
	}

	if !d.IsNewResource() && user == nil {
		log.Printf("[WARN] AppStream User (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	d.Set("arn", user.Arn)
	d.Set("authentication_type", user.AuthenticationType)
	d.Set("created_time", aws.TimeValue(user.CreatedTime).Format(time.RFC3339))
	d.Set("enabled", user.Enabled)
	d.Set("first_name", user.FirstName)

	d.Set("last_name", user.LastName)
	d.Set("status", user.Status)
	d.Set("user_name", user.UserName)

	return nil
}

func resourceUserUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).AppStreamConn

	userName, authType, err := DecodeUserID(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error decoding id AppStream User (%s): %w", d.Id(), err))
	}

	if d.HasChange("enabled") {
		if d.Get("enabled").(bool) {
			input := &appstream.EnableUserInput{
				AuthenticationType: aws.String(authType),
				UserName:           aws.String(userName),
			}

			_, err = conn.EnableUserWithContext(ctx, input)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error enabling AppStream User (%s): %w", d.Id(), err))
			}
		} else {
			input := &appstream.DisableUserInput{
				AuthenticationType: aws.String(authType),
				UserName:           aws.String(userName),
			}

			_, err = conn.DisableUserWithContext(ctx, input)
			if err != nil {
				return diag.FromErr(fmt.Errorf("error disabling AppStream User (%s): %w", d.Id(), err))
			}
		}

	}

	return nil
}

func resourceUserDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).AppStreamConn

	userName, authType, err := DecodeUserID(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error decoding id AppStream User (%s): %w", d.Id(), err))
	}

	_, err = conn.DeleteUserWithContext(ctx, &appstream.DeleteUserInput{
		AuthenticationType: aws.String(authType),
		UserName:           aws.String(userName),
	})

	if err != nil {
		if tfawserr.ErrCodeEquals(err, appstream.ErrCodeResourceNotFoundException) {
			return nil
		}
		return diag.FromErr(fmt.Errorf("error deleting AppStream User (%s): %w", d.Id(), err))
	}

	return nil
}

func EncodeUserID(userName, authType string) string {
	return fmt.Sprintf("%s/%s", userName, authType)
}

func DecodeUserID(id string) (string, string, error) {
	idParts := strings.SplitN(id, "/", 2)
	if len(idParts) != 2 {
		return "", "", fmt.Errorf("expected ID in format UserName/AuthenticationType, received: %s", id)
	}
	return idParts[0], idParts[1], nil
}
