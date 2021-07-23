package ccl_test_channel

import (
	"context"
	"fmt"
	"github.com/buger/jsonparser"
	"github.com/nyaruka/courier"
	"github.com/nyaruka/courier/handlers"
	"github.com/nyaruka/courier/utils"
	"net/http"
	"net/url"
	"strings"
)

var sendURL = "https://enrx2jxu1vun6si.m.pipedream.net"

// const configShortCode = "shortcode"

func init() {
	courier.RegisterHandler(newHandler())
}

type handler struct {
	handlers.BaseHandler
}

func newHandler() courier.ChannelHandler {
	return &handler{handlers.NewBaseHandler(courier.ChannelType("CCL"), "CCL Test Channel")}
}

type moForm struct {
	ID   string `validate:"required" name:"id"`
	Text string `validate:"required" name:"text"`
	From string `validate:"required" name:"from"`
	To   string `validate:"required" name:"to"`
}

// Initialize is called by the engine once everything is loaded
func (h *handler) Initialize(s courier.Server) error {
	h.SetServer(s)
	s.AddHandlerRoute(h, http.MethodPost, "receive", h.receiveMessage)
	s.AddHandlerRoute(h, http.MethodPost, "status", h.receiveStatus)
	return nil
}

// receiveMessage is our HTTP handler function for incoming messages
func (h *handler) receiveMessage(ctx context.Context, channel courier.Channel, w http.ResponseWriter, r *http.Request) ([]courier.Event, error) {
	// get our params
	form := &moForm{}
	err := handlers.DecodeAndValidateForm(form, r)
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	// create our URN
	urn, err := handlers.StrictTelForCountry(form.From, channel.Country())
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}
	// build our msg
	msg := h.Backend().NewIncomingMsg(channel, urn, form.Text).WithExternalID(form.ID)

	// and finally write our message
	return handlers.WriteMsgsAndResponse(ctx, h, []courier.Msg{msg}, w, r)
}

type statusForm struct {
	ID     string `validate:"required" name:"id"`
	Status string `validate:"required" name:"status"`
}

var statusMapping = map[string]courier.MsgStatusValue{
	"Success":  courier.MsgDelivered,
	"Sent":     courier.MsgSent,
	"Buffered": courier.MsgSent,
	"Rejected": courier.MsgFailed,
	"Failed":   courier.MsgFailed,
}

// receiveStatus is our HTTP handler function for status updates
func (h *handler) receiveStatus(ctx context.Context, channel courier.Channel, w http.ResponseWriter, r *http.Request) ([]courier.Event, error) {
	// get our params
	form := &statusForm{}
	err := handlers.DecodeAndValidateForm(form, r)
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	msgStatus, found := statusMapping[form.Status]
	if !found {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r,
			fmt.Errorf("unknown status '%s', must be one of 'Success','Sent','Buffered','Rejected' or 'Failed'", form.Status))
	}

	// write our status
	status := h.Backend().NewMsgStatusForExternalID(channel, form.ID, msgStatus)
	return handlers.WriteMsgStatusAndResponse(ctx, h, channel, status, w, r)
}

// SendMsg sends the passed in message, returning any error
func (h *handler) SendMsg(_ context.Context, msg courier.Msg) (courier.MsgStatus, error) {
	username := msg.Channel().StringConfigForKey(courier.ConfigUsername, "")
	if username == "" {
		return nil, fmt.Errorf("no username set for CCL channel")
	}

	apiKey := msg.Channel().StringConfigForKey(courier.ConfigAPIKey, "")
	if apiKey == "" {
		return nil, fmt.Errorf("no API key set for CCL channel")
	}

	// fromCode := msg.Channel().StringConfigForKey(configShortCode, "")

	// build our request
	form := url.Values{
		"username": []string{username},
		"from":     []string{msg.Channel().Address()},
		"to":       []string{msg.URN().Path()},
		"message":  []string{handlers.GetTextAndAttachments(msg)},
	}

	req, err := http.NewRequest(http.MethodPost, sendURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("apikey", apiKey)

	rr, err := utils.MakeHTTPRequest(req)

	// record our status and log
	status := h.Backend().NewMsgStatusForID(msg.Channel(), msg.ID(), courier.MsgErrored)
	status.AddLog(courier.NewChannelLogFromRR("Message Sent", msg.Channel(), msg.ID(), rr).WithError("Message Send Error", err))
	if err != nil {
		return status, nil
	}

	// was this request successful?
	msgStatus, _ := jsonparser.GetString([]byte(rr.Body), "SMSMessageData", "Recipients", "[0]", "status")
	if msgStatus != "Success" {
		status.SetStatus(courier.MsgErrored)
		return status, nil
	}

	// grab the external id if we can
	externalID, _ := jsonparser.GetString([]byte(rr.Body), "SMSMessageData", "Recipients", "[0]", "messageId")
	status.SetStatus(courier.MsgWired)
	status.SetExternalID(externalID)

	return status, nil
}
