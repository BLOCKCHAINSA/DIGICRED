using System;
using BChain.Core;
using BChain.Core.Models;
using BChain.Core.Models.SimpleAssets;
using BChain.SmartContract.Runtime;
using BChain.SmartContract.Runtime.Attributes;
using BChain.SmartContract.Runtime.Exceptions;

namespace DigiCred.Contracts
{
    [Contract(Version = 1000, Description = "DigiCred Cryptographically Secure Currency")]
    public sealed class DCX : Smart
    {
        public DCX() { }

        // we're creating a coin, so currency (NOT TOKEN!)
        public override ContractType GetContractType() => ContractType.Currency;

        // name of our coin
        public string Name => (string)@in.assetName;

        // symbol for our coin
        public string Symbol => (string)@in.assetSymbol;

        // active from 2018/1/1
        public override DateTime ActiveFromDateTime => DateTime.MinValue;

        // active till end of time really.
        public override DateTime ActiveToDateTime => DateTime.MaxValue;

        protected override bool When()
        {
            if (@in.addressFrom == ContractAddress)
            {
                return true;
            }

            return false;
        }

        protected override bool Do()
        {
            Mint(@in.Output);

            return true;
        }

        #region Directives

        [ContractDirective(Version = 2, Description = "Mints a new DCX coin to the contract.")]
        public override void Mint(ContractParameters parameters)
        {
            var masterFingerprint = (string)@in.fingerPrint;
            var userFingerprint = (string)parameters[ContractParameterTypes.__fingerPrint];

            if (masterFingerprint != userFingerprint)
            {
                throw new DirectiveCallFailed("Fingerprints do not match. Authentication failed.");
            }

            var fromAddress = (Address)parameters[ContractParameterTypes.__addressFrom];

            if (fromAddress != ContractAddress)
            {
                throw new DirectiveCallFailed("Caller address is not allowed.");
            }

            var supplyLimit = (long)@in.supplyLimit;
            var initialSupply = (long)@in.initialSupply;
            var currentSupply = (long)@in.currentSupply;

            var amount = (long)@in.amount;

            if (initialSupply > (supplyLimit - currentSupply))
            {
                throw new DirectiveCallFailed($"The supply limit of {string.Format("{0:N0}", supplyLimit)} has been reached. No further minting is possible.");
            }

            // On Success of transaction, update current supply
            var _ = new Action<bool>((success) =>
            {
                if (success)
                {
                    @in.currentSupply = currentSupply + amount;
                }
            });

            bmx
                .Asset()
                .Issue()
                .Params((coin) =>
                {
                    coin.Symbol = Symbol;
                    coin.ContractAddress = fromAddress;
                    coin.To = ContractAddress;
                    coin.Fingerprint = masterFingerprint;
                    coin.FromFingerprint = masterFingerprint;
                    coin.ToFingerprint = masterFingerprint;
                    coin.Amount = initialSupply;
                    coin.Name = Name;
                })
                .From(fromAddress, masterFingerprint)
                .To(ContractAddress, masterFingerprint)
                .Encrypt()
                .Execute()
                .Go(_);
        }

        [ContractDirective(Version = 2, Description = "Issues a DCX coin to individual from the contract.")]
        public override void Issue(ContractParameters parameters)
        {
            var fromAddress = (Address)parameters[ContractParameterTypes.__addressFrom];

            if (fromAddress != (string)OwnerInitiationAddress)
            {
                throw new DirectiveCallFailed($"Not allowed to issue from here.");
            }

            // from directive input parameters
            var toAddress = (Address)parameters[ContractParameterTypes.__addressTo];
            var amount = (long)parameters[ContractParameterTypes.__amount];

            // from contract input parameters
            var supplyLimit = (long)@in.supplyLimit;
            var currentSupply = (long)@in.currentSupply;

            if (amount > (supplyLimit-currentSupply))
            {
                throw new DirectiveCallFailed("Amount exceeds supply.");
            }

            if (currentSupply < supplyLimit)
            {
                // On Success of transaction, update current supply
                var _ = new Action<bool>((success) =>
                {
                    if (success)
                    {
                        @out.currentSupply = (currentSupply + amount);
                    }
                });

                var fingerprint = (string)@in.fingerPrint;
                var masterFingerprint = (string)parameters["FromFingerprint"];
                var userFingerprint = (string)parameters["ToFingerprint"];

                bmx
                    .Asset()
                    .Transfer()
                    .Params((coin) =>
                    {
                        coin.Symbol = Symbol;
                        coin.Amount = amount;
                        coin.ContractAddress = ContractAddress;
                        coin.From = fromAddress;
                        coin.To = toAddress;
                        coin.FromFingerprint = masterFingerprint;
                        coin.ToFingerprint = userFingerprint;
                        coin.Fingerprint = fingerprint;
                        coin.Name = Name;
                    })
                    .From(fromAddress, masterFingerprint)
                    .To(toAddress, userFingerprint)
                    .Encrypt()
                    .Execute()
                    .Go(_);
            }
        }

        #endregion
    }
}
