package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type BaseClient struct {
	HTTP      *http.Client
	Endpoint  string
	Transport *http.Transport
	Token     string
	User      string
	Headers   []Header // headers
}

type Header struct {
	Key   string
	Value string
}

func NewBaseClient(url string, timeout time.Duration) *BaseClient {
	hClient := &http.Client{}
	if timeout > 0 {
		hClient.Timeout = timeout
	}

	client := &BaseClient{
		HTTP:      hClient,
		Endpoint:  url,
		Transport: &http.Transport{},
	}

	return client
}

func (c *BaseClient) WithHeader(key string, value string) *BaseClient {
	if c.Headers == nil {
		c.Headers = []Header{{Key: key, Value: value}}
		return c
	}
	c.Headers = append(c.Headers, Header{Key: key, Value: value})
	return c
}

func (c *BaseClient) WithTokenAndUser(token, user string) *BaseClient {
	c.Token = token
	c.User = user
	return c
}

func (c *BaseClient) Get(ctx context.Context, pathWithQuery string, out interface{}) error {
	var err error
	_, err = c.request(ctx, http.MethodGet, pathWithQuery, nil, out, nil)
	return err
}

func (c *BaseClient) Put(ctx context.Context, pathWithQuery string, in, out interface{}) error {
	var err error
	_, err = c.request(ctx, http.MethodPut, pathWithQuery, in, out, nil)
	return err
}

func (c *BaseClient) Post(ctx context.Context, pathWithQuery string, in, out interface{}) error {
	var err error
	_, err = c.request(ctx, http.MethodPost, pathWithQuery, in, out, nil)
	return err
}

func (c *BaseClient) Delete(ctx context.Context, pathWithQuery string, in, out interface{}) error {
	var err error
	_, err = c.request(ctx, http.MethodDelete, pathWithQuery, in, out, nil)
	return err
}

func (c *BaseClient) Import(ctx context.Context, pathWithQuery string, in []byte, out interface{}) error {
	_, err := c.request(ctx, http.MethodPost, pathWithQuery, nil, out, in)
	return err
}

func (c *BaseClient) Exporter(ctx context.Context, pathWithQuery string) ([]byte, error) {
	return c.request(ctx, http.MethodGet, pathWithQuery, nil, nil, nil)
}

func (c *BaseClient) request(
	ctx context.Context,
	method string,
	pathWithQuery string,
	requestObj,
	responseObj interface{},
	rawRequestObj []byte,
) (raw []byte, err error) {
	var body io.Reader = http.NoBody
	if requestObj != nil {
		var outData []byte
		outData, err = json.Marshal(requestObj)
		if err != nil {
			return
		}
		body = bytes.NewBuffer(outData)
	}

	if rawRequestObj != nil {
		body = bytes.NewBuffer(rawRequestObj)
	}

	var request *http.Request
	request, err = http.NewRequest(method, Joins(c.Endpoint, pathWithQuery), body)
	if err != nil {
		return
	}

	if rawRequestObj == nil {
		request.Header.Add("Content-Type", "application/json")
	} else {
		request.Header.Add("Content-Length", strconv.Itoa(len(rawRequestObj)))
	}
	// 注入headers
	for _, obj := range c.Headers {
		request.Header.Add(obj.Key, obj.Value)
	}
	if len(c.Token) != 0 {
		request.Header.Add("X-Token", c.Token)
	}

	if len(c.User) != 0 {
		request.Header.Add("X-User", c.User)
	}

	var resp *http.Response
	resp, err = c.doRequest(ctx, request)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	if responseObj != nil {
		err = json.NewDecoder(resp.Body).Decode(responseObj)
		if err != nil {
			return
		}
		return
	}

	raw, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return
}

func (c *BaseClient) doRequest(context context.Context, request *http.Request) (*http.Response, error) {
	withContext := request.WithContext(context)

	response, err := c.HTTP.Do(withContext)
	if err != nil {
		return response, err
	}

	err = checkError(response)
	return response, err
}

func checkError(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(response.Body)
		return errors.New(string(data))
	}
	return nil
}

func (c *BaseClient) Close() {
	if c.Transport != nil {
		// When the http transport goes out of scope, the underlying goroutines responsible
		// for handling keep-alive connections are not closed automatically.
		// Since this client gets recreated frequently we would effectively be leaking goroutines.
		// Let's make sure this does not happen by closing idle connections.
		c.Transport.CloseIdleConnections()
	}
}

func (c *BaseClient) Equal(c2 *BaseClient) bool {
	// handle nil case
	if c2 == nil && c != nil {
		return false
	}

	// compare endpoint and user creds
	return c.Endpoint == c2.Endpoint
}

func Joins(args ...string) string {
	var str strings.Builder
	for _, arg := range args {
		str.WriteString(arg)
	}
	return str.String()
}

func AddQueryParam(params, param string) string {
	if !strings.Contains(params, "?") {
		params = params + "?" + param
		return params
	}

	return params + "&" + param
}

// 添加新的方法用于发送原始数据
func (c *BaseClient) PostRawData(ctx context.Context, pathWithQuery string, data string, params map[string]string) error {
	// 构建查询参数
	finalPath := pathWithQuery
	for key, value := range params {
		finalPath = AddQueryParam(finalPath, key+"="+value)
	}

	// 使用 strings.NewReader 直接发送原始数据
	_, err := c.request(
		ctx,
		http.MethodPost,
		finalPath,
		nil,
		nil,
		[]byte(data),
	)
	return err
}
