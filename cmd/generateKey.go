/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"main/crypto"

	"github.com/spf13/cobra"
)

// generateKeyCmd represents the generateKey command
var generateKeyCmd = &cobra.Command{
	Use:   "generateKey",
	Short: "Generates an aes key",
	Long: `
Don't even know who aes is? Boy, is this command for you.

This will randomly generate an aes key for you that's even more random than that
one awkward co-worker. With keys this random, there's NO WAY Eve, or any of
those cyber wack-jobs* will ever sniff your secrets.
*(https://en.wikipedia.org/wiki/Alice_and_Bob#Cast_of_characters)
`,
	Run: func(cmd *cobra.Command, args []string) {
		crypto.GenerateKey()
	},
}

func init() {
	rootCmd.AddCommand(generateKeyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateKeyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateKeyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
